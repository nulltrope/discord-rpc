# Mute Voice Example

A simple example of using the `discord-rpc` library to mute the microphone of your Discord client.

## Pre-requisites

### Go Version

Ensure you have Go version `1.20+` installed locally to run this test.

### Discord Application

You must have created a Discord Application that will be used to authenticate with your client. 

To create a simple test application for this demo, do the following (note: you should be logged into the same account you will be logged into on your client):
1. Visit the [Discord Developers Applications page](https://discord.com/developers/applications) and click "New Application" at the top right, choosing any name e.g. `mute-mic-test`.
2. On the "OAuth2 > General" page for your application, copy your Client ID and Client Secret (you might have to click "Reset Secret" to get it to show) and save them somewhere safe for later.
3. On the same page, click "Add Redirect" and set it to `http://localhost:8080/auth`.
4. On the same page, under "Default Authorization Link", set the "Authorization Method" to "In-app Authorization", check "applications.commands" and finally click "Save Changes".

## Running

1. In the terminal where you'll be running the example, set the environment variables `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET` to the Application's Client ID and Client Secret you created above.
2. Ensure you have a Discord client open, your mic is unmuted, and you are logged into the same account you created the test application with above.
3. From this directory, run `go run main.go`
4. If all went well, your client should prompt you to authorize the application you created, and upon clicking "Authorize" you should see your mic now muted. Nice!
