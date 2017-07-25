package rancherauthentication

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/v2"
	k8sAuthentication "k8s.io/client-go/pkg/apis/authentication"
)

const (
	cattleURLEnv          = "CATTLE_URL"
	cattleURLAccessKeyEnv = "CATTLE_ACCESS_KEY"
	cattleURLSecretKeyEnv = "CATTLE_SECRET_KEY"

	kubernetesMasterGroup = "system:masters"
	adminUser             = "admin"
	bootstrapUser         = "bootstrap"
)

type Provider struct {
	url            string
	client         *client.RancherClient
	bootstrapToken string
	httpClient     *http.Client
}

func NewProvider(bootstrapToken string) (*Provider, error) {
	url, err := client.NormalizeUrl(os.Getenv(cattleURLEnv))
	if err != nil {
		return nil, err
	}
	rancherClient, err := client.NewRancherClient(&client.ClientOpts{
		Url:       url,
		AccessKey: os.Getenv(cattleURLAccessKeyEnv),
		SecretKey: os.Getenv(cattleURLSecretKeyEnv),
	})
	return &Provider{
		url:            url,
		client:         rancherClient,
		bootstrapToken: bootstrapToken,
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}, err
}

func (p *Provider) Lookup(token string) (*k8sAuthentication.UserInfo, error) {
	if token == "" {
		return nil, nil
	}

	log.Debugf("Raw token: %s", token)

	if token == p.bootstrapToken {
		log.Debug("Raw token is the same as bootstrap token")
		return &k8sAuthentication.UserInfo{
			Username: bootstrapUser,
			Groups:   []string{kubernetesMasterGroup},
		}, nil
	}

	if p.authDisabled() {
		log.Debug("Detected that auth is disabled")
		return &k8sAuthentication.UserInfo{
			Username: adminUser,
			Groups:   []string{kubernetesMasterGroup},
		}, nil
	}

	decodedTokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	token = string(decodedTokenBytes)

	log.Debugf("Decoded token: %s", token)

	req, err := http.NewRequest("GET", p.url+"/identity", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var identityCollection client.IdentityCollection
	if err = json.Unmarshal(data, &identityCollection); err != nil {
		return nil, err
	}

	environmentIdentities, err := getEnvironmentIdentities(p.client)
	if err != nil {
		return nil, err
	}

	authenticated, master := shouldBeAuthenticated(identityCollection, environmentIdentities)
	if !authenticated {
		log.Debug("Not authenticated")
		return nil, nil
	}

	userInfo := getUserInfoFromIdentityCollection(&identityCollection)
	if master {
		log.Debug("Authenticated as master")
		userInfo.Groups = append(userInfo.Groups, kubernetesMasterGroup)
	} else {
		log.Debug("Not authenticated as master")
	}

	return &userInfo, nil
}

func (p *Provider) authDisabled() bool {
	req, err := http.NewRequest("GET", p.url+"/settings/api.security.enabled", nil)
	if err != nil {
		return false
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var setting client.Setting
	if err = json.Unmarshal(data, &setting); err != nil {
		return false
	}

	return setting.Value == "false"
}
