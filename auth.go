package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/prometheus/common/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"os"
	"strings"
)

var (
	errMissingMetadata = status.Errorf(codes.InvalidArgument, "missing metadata")
	errInvalidScope    = status.Errorf(codes.Unauthenticated, "invalid scope")
	errInvalidToken    = status.Errorf(codes.Unauthenticated, "invalid token")
	errInvalidAudience = status.Errorf(codes.Unauthenticated, "invalid audience")
	errInvalidIssuer   = status.Errorf(codes.Unauthenticated, "invalid issuer")
	errInvalidSubject  = status.Errorf(codes.Unauthenticated, "invalid subject")
	errMissingToken    = status.Errorf(codes.NotFound, "missing token")
	Key                *rsa.PublicKey
)

type MyCustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

func EnsureValidToken(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errMissingMetadata
	}

	token, claims, err := ParseToken(md["authorization"])
	if err != nil {
		log.Errorf("failed to parse token: %s", err)
	}

	if !token.Valid {
		return nil, errInvalidToken
	}

	if !claims.HasScope(os.Getenv("AUTH0_SCOPE")) {
		return nil, errInvalidScope
	}

	if !claims.VerifyAudience(os.Getenv("AUTH0_AUDIENCE"), true) {
		return nil, errInvalidAudience
	}

	if !claims.VerifyIssuer(os.Getenv("AUTH0_ISSUER"), true) {
		return nil, errInvalidIssuer
	}

	if claims.Subject != os.Getenv("AUTH0_SUBJECT") {
		return nil, errInvalidSubject
	}

	return handler(ctx, req)
}

func ParseToken(authorization []string) (*jwt.Token, *MyCustomClaims, error) {
	if len(authorization) < 1 {
		return nil, nil, errMissingToken
	}
	accessToken := strings.TrimPrefix(authorization[0], "Bearer ")

	claimsStruct := MyCustomClaims{}
	token, err := jwt.ParseWithClaims(
		accessToken,
		&claimsStruct,
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodRSA)
			if !ok {
				return nil, fmt.Errorf("unexpected token signing method")
			}

			return Key, nil
		},
	)
	if err != nil {
		return nil, nil, errInvalidToken
	}

	return token, &claimsStruct, nil
}

func (c MyCustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}
