package main

import "github.com/dutchcoders/check-email-settings/cmd"

func main() {
	app := cmd.New()
	app.RunAndExitOnError()
}
