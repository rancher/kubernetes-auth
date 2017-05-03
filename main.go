package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/rancher/kubernetes-auth/authentication"
	"github.com/rancher/kubernetes-auth/authentication/rancher"
	"github.com/rancher/kubernetes-auth/authentication/test"
	"github.com/rancher/kubernetes-auth/handlers"
	"github.com/urfave/cli"
)

var VERSION = "v0.0.0-dev"

func main() {
	app := cli.NewApp()
	app.Name = "kubernetes-auth"
	app.Version = VERSION
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name: "debug,d",
		},
		cli.BoolFlag{
			Name: "test-authentication",
		},
		cli.StringFlag{
			Name: "evaluate-token",
		},
	}
	app.Action = func(c *cli.Context) error {
		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		bootstrapToken := strings.TrimSpace(string(bytes))

		if bootstrapToken != "" {
			log.Info("Bootstrap token read from stdin")
		}

		var provider authentication.Provider
		if c.Bool("test-authentication") {
			provider = &testauthentication.Provider{}
		} else {
			var err error
			provider, err = rancherauthentication.NewProvider(bootstrapToken)
			if err != nil {
				return err
			}
		}

		evaluateToken := c.String("evaluate-token")
		if evaluateToken != "" {
			userInfo, err := provider.Lookup(evaluateToken)
			if err != nil {
				return err
			}
			if userInfo == nil {
				return fmt.Errorf("Failed to evaluate token %s", evaluateToken)
			}
			fmt.Println("Username", userInfo.Username)
			fmt.Println("Groups", userInfo.Groups)
			return nil
		}

		http.HandleFunc("/", handlers.Authentication(provider))
		return http.ListenAndServe(":80", nil)
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
