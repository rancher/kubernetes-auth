package authentication

import "k8s.io/client-go/pkg/apis/authentication"

type Provider interface {
	Lookup(token string) (*authentication.UserInfo, error)
}
