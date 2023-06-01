package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/nulltrope/discord-rpc/client"
	"github.com/nulltrope/discord-rpc/rpc"
)

type muteCmdArgs struct {
	Mute bool `json:"mute"`
}

func main() {
	client := client.NewOAuthClient(os.Getenv("DISCORD_CLIENT_ID"), os.Getenv("DISCORD_CLIENT_SECRET"), client.DefaultOAuthScopes)

	payload, err := client.Login()
	if err != nil {
		log.Fatalln(err)
	}

	if payload.Evt == "READY" {
		var readyData rpc.ReadyEvtData
		if err := json.Unmarshal(*payload.RawData, &readyData); err == nil {
			log.Printf("Logged in with user: id='%s', name='%s'", readyData.User.Id, readyData.User.Username)
		}
	}

	muteCmd := &rpc.Payload{
		Args: muteCmdArgs{
			Mute: true,
		},
		Cmd: "SET_VOICE_SETTINGS",
	}

	err = client.Send(muteCmd)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = client.Receive()
	if err != nil {
		log.Fatalln(err)
	}
}
