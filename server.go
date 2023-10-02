package auth

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log"
	"strings"
)

type Authorizer struct {
	ClientID     string
	ClientSecret string
	Audience     string
	Issuer       string
	Subject      string
	Jwks         *keyfunc.JWKS
	TokenURL     string
	Token        *oauth2.Token
}

type Claims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

func NewAuthorizer(audience string, issuer string, jwksURL string) *Authorizer {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err)
	}

	return &Authorizer{
		Audience: audience,
		Issuer:   issuer,
		Jwks:     jwks,
	}
}

func (a *Authorizer) EnsureValidToken(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errMissingMetadata
	}

	token, claims, err := a.ParseToken(md["authorization"])
	if err != nil {
		fmt.Errorf("failed to parse token: %s", err)
	}

	if !token.Valid {
		return nil, errInvalidToken
	}

	if !claims.VerifyAudience(a.Audience, true) {
		return nil, errInvalidAudience
	}

	if !claims.VerifyIssuer(a.Issuer, true) {
		return nil, errInvalidIssuer
	}

	return handler(ctx, req)
}

func (a *Authorizer) ParseToken(authorization []string) (*jwt.Token, *Claims, error) {
	if len(authorization) < 1 {
		return nil, nil, errMissingToken
	}
	accessToken := strings.TrimPrefix(authorization[0], "Bearer ")

	token, err := jwt.ParseWithClaims(accessToken, &Claims{}, a.Jwks.Keyfunc)
	if err != nil {
		return nil, nil, errInvalidToken
	}

	return token, token.Claims.(*Claims), nil
}

func ParseTokenUnverified(token string) (*jwt.Token, error) {
	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, Claims{})
	if err != nil {
		return nil, err
	}

	return parsedToken, nil
}

func (c Claims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}
