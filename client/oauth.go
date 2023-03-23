package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nulltrope/discord-rpc/rpc"
	"github.com/nulltrope/discord-rpc/transport"
	"github.com/nulltrope/discord-rpc/util"
)

const (
	defaultOAuthTokenAddress = "https://discord.com/api/oauth2/token"
	defaultOAuthRedirectUri  = "http://localhost:8080/auth"
)

var (
	DefaultOAuthScopes = []string{"rpc"}
)

// OAuthInfo stores the OAuth token response
type OAuthInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// OAuthClient is an RPC client capable of performing the OAuth login flow
type OAuthClient struct {
	ClientId     string
	ClientSecret string
	Scopes       []string
	TokenAddress string
	RedirectURI  string
	AuthInfo     *OAuthInfo
	HTTPClient   *http.Client
	Transport    Transport
}

type Transport interface {
	Connect(string) error
	Write([]byte) error
	Read() ([]byte, error)
}

// NewOAuthClient creates a new rpc client capable of performing the OAuth login flow
// If you wish to customize settings beyond this functions arguments, it's recommended
// you call this function first, then override the struct's fields to ensure mandatory
// fields exist/avoid exceptions.
func NewOAuthClient(clientId, clientSecret string, scopes []string) *OAuthClient {
	return &OAuthClient{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		TokenAddress: defaultOAuthTokenAddress,
		RedirectURI:  defaultOAuthRedirectUri,
		AuthInfo:     nil,
		HTTPClient:   &http.Client{},
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

// Args for the Authorize command request payload
// https://discord.com/developers/docs/topics/rpc#authenticate-authenticate-argument-structure
type authorizeCmdArgs struct {
	ClientId string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// Data for the Authorize command response payload
// https://discord.com/developers/docs/topics/rpc#authorize-example-authorize-response-payload
type authorizeCmdData struct {
	Code string `json:"code"`
}

type authenticateCmdArgs struct {
	AccessToken string `json:"access_token"`
}

type authenticateCmdData struct {
	Scopes  []string `json:"scopes"`
	Expires string   `json:"expires"`
	// Excluding additional fields which we don't care about
}

// Login will initiate the OAuth flow over the given transport
func (c *OAuthClient) Login() error {
	// Ensure we're connected
	connectErr := c.transport().Connect(c.ClientId)
	if connectErr != nil {
		return connectErr
	}

	if c.AuthInfo == nil {
		// We've never logged in before, do full flow
		return c.doLogin()
	} else {
		// Either we already logged in or somebody provided auth info
		_, err := c.authenticate(c.AuthInfo.AccessToken)
		if err != nil {
			return fmt.Errorf("error sending authenticate request: %v", err)
		}
	}
	return nil
}

func (c *OAuthClient) doLogin() error {
	authzData, err := c.authorize()
	if err != nil {
		return fmt.Errorf("error sending authorize request: %v", err)
	}

	authInfo, err := c.getToken(authzData.Code)
	if err != nil {
		return fmt.Errorf("error exchanging code for token: %v", err)
	}

	_, err = c.authenticate(authInfo.AccessToken)
	if err != nil {
		return fmt.Errorf("error sending authenticate request: %v", err)
	}

	c.AuthInfo = authInfo
	return nil
}

func (c *OAuthClient) authorize() (*authorizeCmdData, error) {
	authzCmd := &rpc.Payload{
		Args: authorizeCmdArgs{
			ClientId: c.ClientId,
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
		return nil, fmt.Errorf("error unmarshalling payload data: %v", err)
	}

	return &payloadData, nil
}

func (c *OAuthClient) getToken(code string) (*OAuthInfo, error) {
	tokenData := url.Values{}
	tokenData.Set("client_id", c.ClientId)
	tokenData.Set("client_secret", c.ClientSecret)
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

	var authInfo OAuthInfo
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
		return nil, fmt.Errorf("error unmarshalling payload data: %v", err)
	}

	return &payloadData, nil
}

// Send a payload over transport
func (c *OAuthClient) Send(payload *rpc.Payload) error {
	if payload.Nonce == "" {
		nonce, nonceErr := util.GenNonce()
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

// Receive a payload over transport, doing basic error checking
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

	payloadErr := payload.Error()
	if payloadErr != nil {
		return &payload, payloadErr
	}

	return &payload, payloadErr
}
