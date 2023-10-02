package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"net/http"
)

type Authenticator struct {
	ClientID     string
	ClientSecret string
	Audience     string
	TokenURL     string
	token        *oauth2.Token `json:"token,omitempty"`
}

type TokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
	GrantType    string `json:"grant_type"`
}

func NewAuthenticator(clientId string, clientSecret string, Audience string, TokenUrl string) *Authenticator {
	return &Authenticator{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Audience:     Audience,
		TokenURL:     TokenUrl,
	}
}

// AuthenticationClientInterceptor New Interceptor
func (a *Authenticator) AuthenticationClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if a.token == nil {
		token, err := a.GetToken()
		if err != nil {
			return err
		}

		a.token = token
	}

	if a.token.Valid() {
		md := metadata.New(map[string]string{
			"authorization": a.token.AccessToken,
		})

		ctx = metadata.NewOutgoingContext(ctx, md)

		return invoker(ctx, method, req, reply, cc, opts...)
	} else {
		token, err := a.GetToken()
		if err != nil {
			return err
		}

		a.token = token

		md := metadata.New(map[string]string{
			"authorization": a.token.AccessToken,
		})

		ctx = metadata.NewOutgoingContext(ctx, md)

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (a *Authenticator) GetToken() (*oauth2.Token, error) {
	var tokenObject oauth2.Token
	data := TokenRequest{
		ClientId:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Audience:     a.Audience,
		GrantType:    "client_credentials",
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", a.TokenURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(responseData, &tokenObject); err != nil {
		return nil, err
	}

	return &tokenObject, nil
}
