package testauthentication

import k8sAuthentication "k8s.io/client-go/pkg/apis/authentication"

var (
	testUserInfo = map[string]k8sAuthentication.UserInfo{
		"test1": k8sAuthentication.UserInfo{
			Username: "test1",
		},
		"test2": k8sAuthentication.UserInfo{
			Username: "test2",
		},
		"test3": k8sAuthentication.UserInfo{
			Username: "test3",
		},
		"admin": k8sAuthentication.UserInfo{
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
