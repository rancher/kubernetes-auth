package rancherauthentication

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/rancher/go-rancher/v2"
	k8sAuthentication "k8s.io/client-go/pkg/apis/authentication"
)

const (
	cattleUrlEnv = "CATTLE_URL"
)

type Provider struct{
	url string
}

func NewProvider() (*Provider, error) {
	url, err := client.NormalizeUrl(os.Getenv(cattleUrlEnv))
	if err != nil {
		return nil, err
	}
	return &Provider{
		url: url,
	}, nil
}

func (p *Provider) Lookup(token string) (*k8sAuthentication.UserInfo, error) {
	// TODO: remove this
	if token == "admin" {
		return &k8sAuthentication.UserInfo{
			Username: "admin",
		}, nil
	}

	decodedTokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	token = string(decodedTokenBytes)

	httpClient := &http.Client{
		Timeout: time.Second * 30,
	}
	// TODO: make sure this URL is always formatted correctly
	req, err := http.NewRequest("GET", p.url+"/identity", nil)
	req.Header.Add("Authorization", token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var identityCollection client.IdentityCollection
	if err = json.Unmarshal(data, &identityCollection); err != nil {
		return nil, err
	}

	// TODO: only works for GitHub, maybe not even for that
	for _, identity := range identityCollection.Data {
		if identity.ExternalIdType == "github_user" {
			return &k8sAuthentication.UserInfo{
				Username: identity.Login,
			}, nil
		}
	}

	return nil, nil
}
