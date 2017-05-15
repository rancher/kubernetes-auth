package healthcheck

import (
	"fmt"
	"net/http"
	"strconv"

	log "github.com/Sirupsen/logrus"
)

func Start(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("Invalid health check port number: %v", port)
	}

	http.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	p := ":" + strconv.Itoa(port)
	log.Infof("Listening for health checks on 0.0.0.0%s/healthcheck", p)
	return http.ListenAndServe(p, nil)
}
