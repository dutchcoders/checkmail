package main

import "github.com/dutchcoders/checkmail/cmd"

func main() {
	app := cmd.New()
	app.RunAndExitOnError()
}
