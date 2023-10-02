package auth

import (
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errMissingMetadata = status.Errorf(codes.InvalidArgument, "missing metadata")
	errInvalidScope    = status.Errorf(codes.Unauthenticated, "invalid scope")
	errInvalidToken    = status.Errorf(codes.Unauthenticated, "invalid token")
	errInvalidAudience = status.Errorf(codes.Unauthenticated, "invalid audience")
	errInvalidIssuer   = status.Errorf(codes.Unauthenticated, jwt.ErrTokenInvalidIssuer.Error())
	errInvalidSubject  = status.Errorf(codes.Unauthenticated, "invalid subject")
	errMissingToken    = status.Errorf(codes.NotFound, "missing token")
)
