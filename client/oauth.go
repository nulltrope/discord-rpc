// Package client provides implementations for interacting with a Discord client over RPC.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nulltrope/discord-rpc/rpc"
	"github.com/nulltrope/discord-rpc/transport"
)

const (
	defaultOAuthTokenAddress = "https://discord.com/api/oauth2/token"
	defaultOAuthRedirectUri  = "http://localhost:8080/auth"
)

var (
	// DefaultOAuthScopes is the minimal scope(s) required for most RPC actions.
	DefaultOAuthScopes = []string{"rpc"}
)

// OAuthToken stores the OAuth token response.
type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// OAuthApp stores the discord application credentials tied to a specific user account
type OAuthApp struct {
	// ClientId is the ID of the Discord application you are authenticating on behalf of.
	ClientId string `json:"client_id"`
	// ClientSecret is the ID of the Discord application you are authenticating on behalf of.
	ClientSecret string `json:"client_secret"`
	// Token holds the token info for this application, if its already been authenticated
	// If you perform the OAuth flow yourself, you can pass the info in here
	// to skip the client performing the login flow for you.
	Token *OAuthToken `json:"token,omitempty"`
}

type UserID string

const UserIDAny = "*"

type OAuthApps map[UserID]OAuthApp

// OAuthClient is a Discord RPC client capable of performing the OAuth login flow.
type OAuthClient struct {
	// TokenAddress is the Discord API endpoint used to retrieve an access token.
	TokenAddress string
	// RedirectURI is the local URI used to complete the OAuth flow.
	RedirectURI string
	// Scopes are the OAuth scopes you are logging in with.
	// See https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes.
	Scopes []string
	// Apps holds the auth info for multiple Discord applications, keyed by User ID.
	// This is needed because Discord only allows RPC from Applications owned by the currently logged-in user.
	// If you plan to switch accounts in your Discord client, you'll need to store the Discord application info
	// for each user account you plan to switch to.
	// If you only plan to use a single user account in your Discord client, you can just key by UserIDAny to not
	// require inputting your user ID in this config.
	Apps OAuthApps
	// HTTPClient is the http client used to perform the OAuth login flow.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client
	// Transport is the underlying transport used to communicate with the Discord client.
	// If nil, transport.DefaultIPC is used.
	Transport Transport
}

// Transport is an interface representing the ability to read/write data to some place.
type Transport interface {
	Connect(string) (*rpc.Payload, error)
	Write([]byte) error
	Read() ([]byte, error)
	Close() error
}

// NewOAuthClient creates a new rpc client capable of performing the OAuth login flow.
func NewOAuthClient(clientId, clientSecret string, scopes []string) *OAuthClient {
	apps := make(OAuthApps)
	apps[UserIDAny] = OAuthApp{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}
	return &OAuthClient{
		TokenAddress: defaultOAuthTokenAddress,
		RedirectURI:  defaultOAuthRedirectUri,
		Scopes:       scopes,
		Apps:         apps,
		HTTPClient:   http.DefaultClient,
		Transport:    transport.DefaultIPC,
	}
}

func NewMultiAccountOAuthClient(apps OAuthApps, scopes []string) *OAuthClient {
	return &OAuthClient{
		TokenAddress: defaultOAuthTokenAddress,
		RedirectURI:  defaultOAuthRedirectUri,
		Scopes:       scopes,
		Apps:         apps,
		HTTPClient:   http.DefaultClient,
		Transport:    transport.DefaultIPC,
	}
}

func (c *OAuthClient) transport() Transport {
	if c.Transport == nil {
		return transport.DefaultIPC
	}
	return c.Transport
}

func (c *OAuthClient) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return &http.Client{}
	}
	return c.HTTPClient
}

func (c *OAuthClient) tokenAddress() string {
	if c.TokenAddress == "" {
		return defaultOAuthTokenAddress
	}
	return c.TokenAddress
}

func (c *OAuthClient) redirectURI() string {
	if c.RedirectURI == "" {
		return defaultOAuthRedirectUri
	}
	return c.RedirectURI
}

// Args for the Authorize command request payload.
// See https://discord.com/developers/docs/topics/rpc#authorize-authorize-argument-structure.
type authorizeCmdArgs struct {
	ClientId string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// Data for the Authorize command response payload.
// See https://discord.com/developers/docs/topics/rpc#authorize-authorize-response-structure.
type authorizeCmdData struct {
	Code string `json:"code"`
}

// Args for the Authenticate command request payload.
// See https://discord.com/developers/docs/topics/rpc#authenticate-authenticate-argument-structure.
type authenticateCmdArgs struct {
	AccessToken string `json:"access_token"`
}

// Data for the Authenticate command response payload.
// See https://discord.com/developers/docs/topics/rpc#authenticate-authenticate-response-structure.
type authenticateCmdData struct {
	Scopes  []string `json:"scopes"`
	Expires string   `json:"expires"`
	// Excluding additional fields which we don't care about
}

// Login will initiate the OAuth flow over the given transport.
// Additionally, the transport will be initialized/connected if not already done.
func (c *OAuthClient) Login() (*rpc.Payload, error) {
	if c.Apps == nil || len(c.Apps) < 1 {
		return nil, errors.New("must specify at least one OAuthApp")
	}

	// We can just use the first app for the initial handshake
	var handshakeApp OAuthApp
	for _, app := range c.Apps {
		handshakeApp = app
		break
	}

	// Make initial connection to get info on the current user
	connectPayload, err := c.transport().Connect(handshakeApp.ClientId)
	if err != nil {
		return connectPayload, fmt.Errorf("initial connect handshake with clientId '%s' failed: %v", handshakeApp.ClientId, err)
	}

	var readyEvtData rpc.ReadyEvtData
	err = json.Unmarshal(*connectPayload.RawData, &readyEvtData)
	if err != nil {
		return connectPayload, err
	}

	// Now we know the current user, get the proper App info for the actual OAuth flow
	var app OAuthApp
	if ourUser, ok := c.Apps[UserID(readyEvtData.User.Id)]; ok {
		// Exact match takes priority
		app = ourUser
	} else if anyUser, ok := c.Apps[UserIDAny]; ok {
		// Else try wildcard ANY login
		app = anyUser
	} else {
		// We have nothing, sad
		return connectPayload, fmt.Errorf("unable to find app for user: %s", readyEvtData.User.Id)
	}

	if app.ClientId != handshakeApp.ClientId {
		// We need to disconnect & re-connect
		err = c.transport().Close()
		if err != nil {
			return connectPayload, fmt.Errorf("unable to close initian conn: %v", err)
		}

		connectPayload, err := c.transport().Connect(app.ClientId)
		if err != nil {
			return connectPayload, fmt.Errorf("app connect handshake with clientId '%s' failed: %v", app.ClientId, err)
		}
	}

	// Check if we have previous login info or need to perform full flow
	if app.Token != nil {
		_, err := c.authenticate(app.Token.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %v", err)
		}
		return connectPayload, nil
	}

	// We've never logged in before, do full flow
	authInfo, err := c.doLogin(app)
	if err != nil {
		return connectPayload, err
	}

	// Save auth info for next time
	app.Token = authInfo
	c.Apps[UserID(readyEvtData.User.Id)] = app
	return connectPayload, nil
}

func (c *OAuthClient) doLogin(app OAuthApp) (*OAuthToken, error) {
	authzData, err := c.authorize(app)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %v", err)
	}

	authInfo, err := c.getToken(app, authzData.Code)
	if err != nil {
		return authInfo, fmt.Errorf("token exchange failed: %v", err)
	}

	_, err = c.authenticate(authInfo.AccessToken)
	if err != nil {
		return authInfo, fmt.Errorf("authentication failed: %v", err)
	}

	return authInfo, nil
}

func (c *OAuthClient) authorize(app OAuthApp) (*authorizeCmdData, error) {
	authzCmd := &rpc.Payload{
		Args: authorizeCmdArgs{
			ClientId: app.ClientId,
			Scopes:   c.Scopes,
		},
		Cmd: "AUTHORIZE",
	}

	err := c.Send(authzCmd)
	if err != nil {
		return nil, err
	}

	payload, err := c.Receive()
	if err != nil {
		return nil, err
	}

	if payload.Cmd != "AUTHORIZE" {
		return nil, fmt.Errorf("expected AUTHORIZE cmd but got %s", payload.Cmd)
	}

	var payloadData authorizeCmdData
	err = json.Unmarshal(*payload.RawData, &payloadData)
	if err != nil {
		return nil, err
	}

	return &payloadData, nil
}

func (c *OAuthClient) getToken(app OAuthApp, code string) (*OAuthToken, error) {
	tokenData := url.Values{}
	tokenData.Set("client_id", app.ClientId)
	tokenData.Set("client_secret", app.ClientSecret)
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", c.redirectURI())

	tokenUri, err := url.ParseRequestURI(c.tokenAddress())
	if err != nil {
		return nil, err
	}

	tokenReq, err := http.NewRequest(http.MethodPost, tokenUri.String(), strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, err
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := c.httpClient().Do(tokenReq)
	if err != nil {
		return nil, err
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected status code: %d", tokenResp.StatusCode)
	}

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, err
	}

	var authInfo OAuthToken
	err = json.Unmarshal(tokenBody, &authInfo)
	if err != nil {
		return nil, err
	}
	return &authInfo, nil
}

func (c *OAuthClient) authenticate(token string) (*authenticateCmdData, error) {
	authnCmd := &rpc.Payload{
		Args: authenticateCmdArgs{
			AccessToken: token,
		},
		Cmd: "AUTHENTICATE",
	}

	err := c.Send(authnCmd)
	if err != nil {
		return nil, err
	}

	payload, err := c.Receive()
	if err != nil {
		return nil, err
	}

	if payload.Cmd != "AUTHENTICATE" {
		return nil, fmt.Errorf("expected AUTHENTICATE cmd but got %s", payload.Cmd)
	}

	var payloadData authenticateCmdData
	err = json.Unmarshal(*payload.RawData, &payloadData)
	if err != nil {
		return nil, err
	}

	return &payloadData, payload.Error()
}

// Send will send an rpc.Payload over the transport.
// If payload.Nonce is not defined, a new Nonce will be generated.
func (c *OAuthClient) Send(payload *rpc.Payload) error {
	if payload.Nonce == "" {
		nonce, nonceErr := rpc.GenNonce()
		if nonceErr != nil {
			return nonceErr
		}
		payload.Nonce = nonce
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return c.transport().Write(data)
}

// Receive will read an rpc.Payload from the transport, returning an error if the payload event type is ERROR.
func (c *OAuthClient) Receive() (*rpc.Payload, error) {
	data, err := c.transport().Read()
	if err != nil {
		return nil, err
	}

	var payload rpc.Payload
	err = json.Unmarshal(data, &payload)
	if err != nil {
		return nil, err
	}

	if err = payload.Error(); err != nil {
		return &payload, err
	}

	return &payload, nil
}
