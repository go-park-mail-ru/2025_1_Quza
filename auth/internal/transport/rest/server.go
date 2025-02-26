package rest

import (
	"net/http"
)

type Server struct {
	httpServer *http.Server
}
