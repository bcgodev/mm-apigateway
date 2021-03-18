package token

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"firebase.google.com/go/v4/auth"
)

type FirebaseToken struct {
	tokenString    *string
	tokenState     firebaseTokenState
	firebaseClient *auth.Client
}

type firebaseTokenState struct {
	sync.Mutex
	state *string
}

func (ftt *firebaseTokenState) setState(state string) {
	ftt.state = &state
}

func (ft *FirebaseToken) GetTokenString() (string, error) {
	if ft.tokenString == nil {
		return "", errors.New("token is nil")
	}
	return *ft.tokenString, nil
}

func (ft *FirebaseToken) ExecuteTokenStateUpdate() error {
	if ft.tokenString == nil {
		return errors.New("token is nil")
	}
	ft.tokenState.Lock()
	go func() {
		defer ft.tokenState.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := ft.firebaseClient.VerifyIDTokenAndCheckRevoked(ctx, *ft.tokenString)
		if err != nil {
			ft.tokenState.setState(err.Error())
			return
		}
		ft.tokenState.setState(OK)
	}()
	return nil
}

// GetTokenState will automatically update state if cached state is nil
func (ft *FirebaseToken) GetTokenState() string {
	if ft.tokenState.state == nil {
		ft.ExecuteTokenStateUpdate()
	}

	ft.tokenState.Lock()
	defer ft.tokenState.Unlock()
	return *ft.tokenState.state
}

// NewFirebaseToken creates a token and excute the token state update procedure
func NewFirebaseToken(authHeader string, client *auth.Client) (Token, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	const BearerSchema = "Bearer "
	var state, tokenString *string
	if authHeader == "" {
		s := "authorization header is not provided"
		state = &s
	} else if !strings.HasPrefix(authHeader, BearerSchema) {
		s := "Not a Bearer token"
		state = &s
	} else {
		s := (authHeader)[len(BearerSchema):]
		tokenString = &s
	}
	firebaseToken := &FirebaseToken{
		firebaseClient: client,
		tokenString:    tokenString,
		tokenState: firebaseTokenState{
			state: state,
		},
	}
	firebaseToken.ExecuteTokenStateUpdate()
	return firebaseToken, nil
}
