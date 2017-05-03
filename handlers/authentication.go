package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	k8sAuthentication "k8s.io/client-go/pkg/apis/authentication"

	log "github.com/Sirupsen/logrus"
	"github.com/rancher/kubernetes-auth/authentication"
)

const (
	APIVersion = "authentication.k8s.io/v1beta1"
	Kind       = "TokenReview"
)

var (
	userInfo = map[string]k8sAuthentication.UserInfo{
		"test": k8sAuthentication.UserInfo{
			Username: "test",
		},
	}
	unauthenticatedResponse = map[string]interface{}{
		"apiVersion": APIVersion,
		"kind":       "TokenReview",
		"status": map[string]interface{}{
			"authenticated": false,
		},
	}
)

func Authentication(provider authentication.Provider) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenReviewResponse, err := reviewAuthentication(provider, w, r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		response, err := json.Marshal(tokenReviewResponse)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		log.Debugf("Authentication response: %s", string(response))
		w.Write(response)
	}
}

func reviewAuthentication(provider authentication.Provider, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	log.Debugf("Authentication request: %s", string(body))

	var tokenReviewRequest k8sAuthentication.TokenReview
	if err = json.Unmarshal(body, &tokenReviewRequest); err != nil {
		return nil, err
	}

	if tokenReviewRequest.APIVersion != APIVersion {
		return nil, fmt.Errorf("Unsupported API version %s", tokenReviewRequest.APIVersion)
	}

	token := strings.TrimSpace(tokenReviewRequest.Spec.Token)

	userInfo, err := provider.Lookup(token)
	if err != nil {
		return nil, err
	}
	if userInfo == nil {
		return unauthenticatedResponse, nil
	}

	return map[string]interface{}{
		"apiVersion": APIVersion,
		"kind":       "TokenReview",
		"status": map[string]interface{}{
			"authenticated": true,
			"user": map[string]interface{}{
				"username": userInfo.Username,
				"groups":   userInfo.Groups,
			},
		},
	}, nil
}
