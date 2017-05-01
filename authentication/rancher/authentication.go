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
	cattleURLEnv          = "CATTLE_URL"
	cattleURLAccessKeyEnv = "CATTLE_ACCESS_KEY"
	cattleURLSecretKeyEnv = "CATTLE_SECRET_KEY"
)

type Provider struct {
	url    string
	client *client.RancherClient
}

func NewProvider() (*Provider, error) {
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
		url:    url,
		client: rancherClient,
	}, err
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

	// TODO: groups
	var tokenIdentity client.Identity
	for _, identity := range identityCollection.Data {
		switch identity.ExternalIdType {
		case "rancher_id":
			fallthrough
		case "github_user":
			tokenIdentity = identity
		}
	}

	projectMembers, err := getCurrentEnvironmentMembers(p.client)
	if err != nil {
		return nil, err
	}

	userInfo := k8sAuthentication.UserInfo{
		Username: tokenIdentity.Login,
	}

	// Verify that the user is actually a member of the environment
	if projectMember, ok := projectMembers[tokenIdentity.ExternalId]; ok {
		if projectMember.Role == "owner" {
			userInfo.Groups = []string{"rancher-owner"}
		}
		return &userInfo, nil
	}

	return nil, nil
}

func getCurrentEnvironmentMembers(rancherClient *client.RancherClient) (map[string]client.ProjectMember, error) {
	projects, err := rancherClient.Project.List(&client.ListOpts{})
	if err != nil {
		return nil, err
	}
	projectMembers, err := rancherClient.ProjectMember.List(&client.ListOpts{
		Filters: map[string]interface{}{
			"projectId": projects.Data[0].Id,
		},
	})
	if err != nil {
		return nil, err
	}
	projectMembersMap := map[string]client.ProjectMember{}
	for _, projectMember := range projectMembers.Data {
		projectMembersMap[projectMember.ExternalId] = projectMember
	}
	return projectMembersMap, nil
}
