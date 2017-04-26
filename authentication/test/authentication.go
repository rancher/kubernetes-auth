package testauthentication

import k8sAuthentication "k8s.io/client-go/pkg/apis/authentication"

var (
	testUserInfo = map[string]k8sAuthentication.UserInfo{
		"test1": {
			Username: "test1",
		},
		"test2": {
			Username: "test2",
		},
		"test3": {
			Username: "test3",
		},
		"admin": {
			Username: "admin",
		},
	}
)

type Provider struct{}

func (p *Provider) Lookup(token string) (*k8sAuthentication.UserInfo, error) {
	userInfo, ok := testUserInfo[token]
	if !ok {
		return nil, nil
	}
	return &userInfo, nil
}
