package main

import (
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

	err := client.Login()
	if err != nil {
		log.Fatalln(err)
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
