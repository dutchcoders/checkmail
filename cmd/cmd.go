package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/minio/cli"
	"github.com/op/go-logging"

	"github.com/dutchcoders/check-email-settings/plugins"
	"strings"
	"sync"
)

var Version = "0.1"
var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
{{end}}{{if .Flags}}
FLAGS:
{{range .Flags}}{{.}}
{{end}}{{end}}
VERSION:
` + Version +
	`{{ "\n"}}`

var log = logging.MustGetLogger("check/cmd")

var globalFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "p,port",
		Usage: "port",
		Value: "127.0.0.1:8080",
	},
	cli.StringFlag{
		Name:  "path",
		Usage: "path to static files",
		Value: "",
	},
	cli.StringFlag{
		Name:  "c,config",
		Usage: "config file",
		Value: "config.toml",
	},
}

type Cmd struct {
	*cli.App
}

func VersionAction(c *cli.Context) {
	fmt.Println(color.YellowString(fmt.Sprintf("Bla: BLA.")))
}

func New() *Cmd {
	app := cli.NewApp()
	app.Name = "Check Email Settings bla bla"
	app.Author = ""
	app.Usage = "Check Email Settings bla bla"
	app.Description = `Audits smtp and email configuration`
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Commands = []cli.Command{
		{
			Name:   "version",
			Action: VersionAction,
		},
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) {
		fmt.Println("Check Email")
		fmt.Println("Verify configuration of domain and email settings.")
		fmt.Println("by DutchSec")
		fmt.Println("----------------")

		for _, p := range plugins.Plugins {
			plugin := p()

			fmt.Printf("---- %s %s\n", plugin.Name(), strings.Repeat("-", 80-len(plugin.Name())))

			wg := sync.WaitGroup{}

			for _, domain := range c.Args()[0:] {
				// only thing, what to do with caching dns client

				wg.Add(1)
				go func() {

					defer wg.Done()

					issues := plugin.Check(domain)

					for issue := range issues {
						if issue.Severity == plugins.SeverityError {
							fmt.Printf("[%s] [%s] %s \n", color.RedString("!!"), domain, issue.Message)
						} else if issue.Severity == plugins.SeverityDebug {
							// fmt.Printf("[%s] [%s] %s \n", "- ", domain, issue.Message)
						} else if issue.Severity == plugins.SeverityWarning {
							fmt.Printf("[%s] [%s] %s \n", color.RedString("! "), domain, issue.Message)
						} else if issue.Severity == plugins.SeverityOK {
							fmt.Printf("[%s] [%s] %s \n", color.GreenString("OK"), domain, issue.Message)
						} else if issue.Severity == plugins.SeverityInfo {
							fmt.Printf("[%s] [%s] %s \n", "  ", domain, issue.Message)
						}
					}
				}()

			}

			wg.Wait()

			fmt.Println("")
		}

		fmt.Println("--------")
	}

	return &Cmd{
		App: app,
	}
}
