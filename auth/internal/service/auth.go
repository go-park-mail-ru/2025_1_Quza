package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/config"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type UserPayload struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type UserClaims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Role     string `json:"role"`
}

type AuthService struct {
	cache        redis.UserCacheInterface
	storage      repository.UserRepositoryInterface
	accessPolicy repository.AccessPolicies
	config       config.Auth
}

func NewAuthService(cache redis.UserCacheInterface,
	storage repository.UserRepositoryInterface,
	accessPolicy repository.AccessPolicies,
	config config.Auth) *AuthService {
	return &AuthService{
		cache:        cache,
		storage:      storage,
		accessPolicy: accessPolicy,
		config:       config,
	}
}

func GenerateToken(info model.UserPayload, secretKey []byte, duration time.Duration) (string, error) {
	claims := model.UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(duration).Unix(),
		},
		Username: info.Username,
		Role:     info.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func VerifyToken(tokenStr string, secretKey []byte) (*model.UserClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&model.UserClaims{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, errors.New("unexpected token signing method")
			}

			return secretKey, nil
		},
	)

	if err != nil {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*model.UserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (s AuthService) Check(ctx context.Context, address string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("metadata is not provided")
	}

	authHeader, ok := md["authorization"]
	if !ok || len(authHeader) == 0 {
		return errors.New("authorization header is not provided")
	}

	if !strings.HasPrefix(authHeader[0], "Bearer ") {
		return errors.New("invalid authorization header format")
	}

	accessToken := strings.TrimPrefix(authHeader[0], "Bearer ")

	claims, err := VerifyToken(accessToken, []byte(s.config.SecretKey))
	if err != nil {
		return errors.New("access token is invalid")
	}

	if access := s.accessPolicy.Check(address, claims.Role); access != nil {
		return fmt.Errorf("access policy is not allowed: %w", access)
	}

	return nil
}

func (s AuthService) GetAccessToken(ctx context.Context, refreshToken string) (*string, error) {
	claims, err := VerifyToken(refreshToken, []byte(s.config.SecretKey))
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "invalid refresh token")
	}

	user, err := s.storage.GetUserByName(ctx, claims.Username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	timeExpiration := s.config.AccessTokenExpire

	accessToken, err := GenerateToken(model.UserPayload{
		Username: user.Name,
		Role:     user.Role,
	},
		[]byte(s.config.SecretKey),
		timeExpiration,
	)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to generate access token")
	}

	return &accessToken, nil
}

func (s AuthService) GetRefreshToken(ctx context.Context, refreshToken string) (*string, error) {
	claims, err := VerifyToken(refreshToken, []byte(s.config.SecretKey))
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "invalid refresh token")
	}

	user, err := s.storage.GetUserByName(ctx, claims.Username)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	timeExpiration := s.config.RefreshTokenExpire

	accessToken, err := GenerateToken(model.UserPayload{
		Username: user.Name,
		Role:     user.Role,
	},
		[]byte(s.config.SecretKey),
		timeExpiration,
	)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to generate access token")
	}

	return &accessToken, nil
}

func (s AuthService) Login(ctx context.Context, user model.User) (*string, error) {
	User, err := s.storage.GetUserByName(ctx, user.Name)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	if User.Password != user.Password {
		return nil, fmt.Errorf("invalid password")
	}

	timeExpiration := s.config.RefreshTokenExpire

	refreshToken, err := GenerateToken(model.UserPayload{
		Username: user.Name,
		Role:     User.Role,
	},
		[]byte(s.config.SecretKey),
		timeExpiration,
	)

	if err != nil {
		return nil, fmt.Errorf("error generate refresh token: %w", err)
	}

	return &refreshToken, nil
}
