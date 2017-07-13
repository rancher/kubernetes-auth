package rancherauthentication

import (
	"fmt"

	"github.com/rancher/go-rancher/v2"
	k8sAuthentication "k8s.io/client-go/pkg/apis/authentication"
)

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

func getEnvironmentIdentities(rancherClient *client.RancherClient) (map[string]client.ProjectMember, error) {
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

func shouldBeAuthenticated(identityCollection client.IdentityCollection, environmentIdentities map[string]client.ProjectMember) (bool, bool) {
	authenticated := false
	master := false

	for _, identity := range identityCollection.Data {
		if environmentIdentity, ok := environmentIdentities[identity.Id]; ok {
			authenticated = true
			if environmentIdentity.Role == "owner" {
				master = true
				break
			}
		}
	}

	return authenticated, master
}
