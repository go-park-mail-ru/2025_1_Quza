package dto

import (
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/grpc/proto/user_v1"
)

const (
	strRoleUnspecified = "ROLE_UNSPECIFIED"
	strUser            = "USER"
	strAdmin           = "ADMIN"
)

func ToUpdateUser(update *user_v1.UpdateRequest) *model.User {
	return &model.User{ID: int(update.GetId()),
		Name:  update.Name.Value,
		Email: update.Email.Value,
		Role:  toModelRole(update.GetRole())}
}

func ToProtoUserProfile(user model.User) *user_v1.GetResponse {
	userRole := role2String(user.Role)

	return &user_v1.GetResponse{
		Id: int64(user.ID),
		User: &user_v1.User{
			Name:  user.Name,
			Email: user.Email,
			Role:  userRole,
		},
	}
}

func role2String(roleStr string) user_v1.Role {
	switch roleStr {
	case strRoleUnspecified:
		return user_v1.Role_ROLE_UNSPECIFIED
	case strUser:
		return user_v1.Role_USER
	case strAdmin:
		return user_v1.Role_ADMIN
	}
	return user_v1.Role_ROLE_UNSPECIFIED
}

func ToModelUser(user *user_v1.CreateRequest) model.User {
	role := toModelRole(user.GetUser().GetRole())

	return model.User{
		Name:     user.GetUser().GetName(),
		Email:    user.GetUser().GetEmail(),
		Role:     role,
		Password: user.Password}
}

func toModelRole(role user_v1.Role) string {
	switch role {
	case user_v1.Role_ROLE_UNSPECIFIED:
		return strRoleUnspecified
	case user_v1.Role_ADMIN:
		return strAdmin
	case user_v1.Role_USER:
		return strUser
	}

	return "ROLE_UNSPECIFIED"
}
