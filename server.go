package apigateway

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"firebase.google.com/go/v4/db"
	"github.com/gin-gonic/gin"
	"github.com/mirror-media/mm-apigateway/config"
	"github.com/mirror-media/mm-apigateway/token"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

type ServiceEndpoints struct {
	UserGraphQL string
}

type Server struct {
	Conf                   *config.Conf
	Engine                 *gin.Engine
	FirebaseApp            *firebase.App
	FirebaseClient         *auth.Client
	FirebaseDatabaseClient *db.Client
	Services               *ServiceEndpoints
	UserSrvToken           token.Token
}

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
}

func (s *Server) Run() error {
	return s.Engine.Run(fmt.Sprintf("%s:%d", s.Conf.Address, s.Conf.Port))
}

func NewServer(c config.Conf) (*Server, error) {

	engine := gin.Default()

	opt := option.WithCredentialsFile(c.FirebaseCredentialFilePath)

	config := &firebase.Config{
		DatabaseURL: c.FirebaseRealtimeDatabaseURL,
	}
	app, err := firebase.NewApp(context.Background(), config, opt)
	if err != nil {
		return nil, fmt.Errorf("error initializing app: %v", err)
	}

	firebaseClient, err := app.Auth(context.Background())
	if err != nil {
		return nil, fmt.Errorf("initialization of Firebase Auth Client encountered error: %s", err.Error())
	}

	dbClient, err := app.Database(context.Background())
	if err != nil {
		return nil, fmt.Errorf("initialization of Firebase Database Client encountered error: %s", err.Error())
	}

	gatewayToken, err := token.NewGatewayToken(c.TokenSecretName, c.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("retrieving of the latest token(%s) encountered error: %s", c.TokenSecretName, err.Error())
	}

	s := &Server{
		Conf:                   &c,
		Engine:                 engine,
		FirebaseApp:            app,
		FirebaseClient:         firebaseClient,
		FirebaseDatabaseClient: dbClient,
		Services: &ServiceEndpoints{
			UserGraphQL: c.ServiceEndpoints.UserGraphQL,
		},
		UserSrvToken: gatewayToken,
	}
	return s, nil
}
