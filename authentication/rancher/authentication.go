package rancherauthentication

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	kubernetesMasterGroup = "system:masters"
)

type Provider struct {
	url            string
	client         *client.RancherClient
	bootstrapToken string
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
	}, err
}

func (p *Provider) Lookup(token string) (*k8sAuthentication.UserInfo, error) {
	if token == "" {
		return nil, nil
	}

	if token == p.bootstrapToken {
		return &k8sAuthentication.UserInfo{
			Username: "bootstrap",
			Groups:   []string{kubernetesMasterGroup},
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

	userInfo := getUserInfoFromIdentityCollection(&identityCollection)

	projectMembers, err := getCurrentEnvironmentMembers(p.client)
	if err != nil {
		return nil, err
	}

	// Verify that the user is actually a member of the environment
	if projectMember, ok := projectMembers[userInfo.UID]; ok {
		// Owners of an environment should be authenticated with the masters group
		if projectMember.Role == "owner" {
			userInfo.Groups = append(userInfo.Groups, kubernetesMasterGroup)
		}
		return &userInfo, nil
	}

	return nil, nil
}

func getUserInfoFromIdentityCollection(collection *client.IdentityCollection) k8sAuthentication.UserInfo {
	var rancherIdentity client.Identity
	var otherIdentity client.Identity
	var groups []string
	for _, identity := range collection.Data {
		if identity.User {
			if identity.ExternalIdType == "rancher_id" {
				rancherIdentity = identity
			} else {
				otherIdentity = identity
			}
		} else {
			groups = append(groups, fmt.Sprintf("%s:%s", identity.ExternalIdType, identity.Login))
		}
	}

	identity := otherIdentity
	if identity.Id == "" && rancherIdentity.Id != "" {
		identity = rancherIdentity
	}

	return k8sAuthentication.UserInfo{
		Username: identity.Login,
		UID:      identity.Id,
		Groups:   groups,
	}
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
		projectMembersMap[projectMember.Id] = projectMember
	}
	return projectMembersMap, nil
}
