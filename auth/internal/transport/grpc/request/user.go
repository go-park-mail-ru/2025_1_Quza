package request

import (
	"errors"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/grpc/proto/user_v1"
)

var (
	ErrBadRequest = errors.New("empty name")
)

func ID(req *user_v1.GetRequest_Id) int {
	return int(req.Id)
}

func Name(req *user_v1.GetRequest_Username) (string, error) {
	name := req.Username
	if name == "" {
		return "", ErrBadRequest
	}

	return name, nil
}
