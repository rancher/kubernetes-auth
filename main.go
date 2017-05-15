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
	"github.com/rancher/kubernetes-auth/healthcheck"
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
		cli.IntFlag{
			Name:   "authentication-webhook-port",
			Value:  80,
			Usage:  "Port to handle Kubernetes authentication webhook",
			EnvVar: "AUTHENTICATION_WEBHOOK_PORT",
		},
		cli.IntFlag{
			Name:   "health-check-port",
			Value:  10240,
			Usage:  "Port to configure an HTTP health check listener on",
			EnvVar: "HEALTH_CHECK_PORT",
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

		resultChan := make(chan error)

		go func(rc chan error) {
			http.HandleFunc("/", handlers.Authentication(provider))
			port := c.Int("authentication-webhook-port")
			rc <- http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
		}(resultChan)

		go func(rc chan error) {
			port := c.Int("health-check-port")
			rc <- healthcheck.Start(port)
		}(resultChan)

		return <-resultChan
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
