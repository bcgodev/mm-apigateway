package apigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/machinebox/graphql"
	"github.com/mirror-media/mm-apigateway/middleware"
	"github.com/mirror-media/mm-apigateway/server"
	"github.com/mirror-media/mm-apigateway/token"
	"golang.org/x/oauth2"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/mirror-media/mm-apigateway/graph"
	"github.com/mirror-media/mm-apigateway/graph/generated"
)

// GetIDTokenOnly is a middleware to construct the token.Token interface
func GetIDTokenOnly(server *server.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := log.WithFields(log.Fields{
			"path": c.FullPath(),
		})
		// Create a Token Instance
		authHeader := c.GetHeader("Authorization")
		firebaseClient := server.FirebaseClient
		token, err := token.NewFirebaseToken(authHeader, firebaseClient)
		if err != nil {
			logger.Info(err)
			c.Next()
			return
		}
		c.Set(middleware.GCtxTokenKey, token)
		c.Next()
	}
}

// AuthenticateIDToken is a middleware to authenticate the request and save the result to the context
func AuthenticateIDToken(server *server.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := log.WithFields(log.Fields{
			"path": c.FullPath(),
		})
		// Create a Token Instance
		t := c.Value(middleware.GCtxTokenKey)
		if t == nil {
			err := errors.New("no token provided")
			logger.Info(err)
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorReply{
				Errors: []Error{{Message: err.Error()}},
			})
			return
		}
		tt := t.(token.Token)

		if tt.GetTokenState() != token.OK {
			logger.Info(tt.GetTokenState())
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorReply{
				Errors: []Error{{Message: tt.GetTokenState()}},
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Because GetTokenState() already fetch the public key and cache it. Here VerifyIDToken() would only verify the signature.
		firebaseClient := server.FirebaseClient
		tokenString, _ := tt.GetTokenString()
		idToken, err := firebaseClient.VerifyIDToken(ctx, tokenString)
		if err != nil {
			logger.Info(err.Error())
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorReply{
				Errors: []Error{{Message: err.Error()}},
			})
			return
		}
		c.Set(middleware.GCtxUserIDKey, idToken.Subject)
		c.Next()
	}
}

func GinContextToContextMiddleware(server *server.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), middleware.CtxGinContexKey, c)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func FirebaseClientToContextMiddleware(server *server.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), middleware.CtxFirebaseClientKey, server.FirebaseClient)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func FirebaseDBClientToContextMiddleware(server *server.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), middleware.CtxFirebaseDatabaseClientKey, server.FirebaseDatabaseClient)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func singleJoiningSlash(a, b string) string {

	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")

	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}

	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()
	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}

	return a.Path + b.Path, apath + bpath

}

func ModifyReverseProxyResponse(c *gin.Context) func(*http.Response) error {
	return func(r *http.Response) error {
		body, err := ioutil.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			return err
		}

		var tokenState string

		tokenSaved, exist := c.Get(middleware.GCtxTokenKey)
		if !exist {
			tokenState = "No Bearer token available"
		} else {
			tokenState = tokenSaved.(token.Token).GetTokenState()
		}

		b, err := json.Marshal(Reply{
			TokenState: tokenState,
			Data:       json.RawMessage(body),
		})

		if err != nil {
			return err
		}

		r.Body = ioutil.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
		return nil
	}
}

func NewSingleHostReverseProxy(target *url.URL, pathBaseToStrip string) func(c *gin.Context) {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		if strings.HasSuffix(pathBaseToStrip, "/") {
			pathBaseToStrip = pathBaseToStrip + "/"
		}
		req.URL.Path = strings.TrimPrefix(req.URL.Path, pathBaseToStrip)
		req.URL.RawPath = strings.TrimPrefix(req.URL.RawPath, pathBaseToStrip)

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)

		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}

		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return func(c *gin.Context) {
		reverseProxy := httputil.ReverseProxy{Director: director}
		reverseProxy.ModifyResponse = ModifyReverseProxyResponse(c)
		reverseProxy.ServeHTTP(c.Writer, c.Request)
	}
}

type Reply struct {
	TokenState interface{} `json:"tokenState"`
	Data       interface{} `json:"data,omitempty"`
}

type Error struct {
	Message string `json:"message,omitempty"`
}
type ErrorReply struct {
	Errors []Error     `json:"errors,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

func SetHealthRoute(server *server.Server) error {

	if server.Conf == nil || server.FirebaseApp == nil {
		return errors.New("config or firebase app is nil")
	}

	router := server.Engine
	router.GET("/health", func(c *gin.Context) {
		c.AbortWithStatus(http.StatusOK)
	})

	return nil
}

// SetRoute sets the routing for the gin engine
func SetRoute(server *server.Server) error {
	apiRouter := server.Engine.Group("/api")

	// Public API
	// v1 api
	v1Router := apiRouter.Group("/v1")
	v1tokenStateRouter := v1Router.Use(GetIDTokenOnly(server))
	v1tokenStateRouter.GET("/tokenState", func(c *gin.Context) {
		t := c.Value(middleware.GCtxTokenKey).(token.Token)
		if t == nil {
			c.JSON(http.StatusBadRequest, Reply{
				TokenState: nil,
			})
			return
		}
		c.JSON(http.StatusOK, Reply{
			TokenState: t.GetTokenState(),
		})
	})

	// Private API
	// v1 User
	// It will save FirebaseClient and FirebaseDBClient to *gin.context, and *gin.context to *context
	v1TokenAuthenticatedWithFirebaseRouter := v1Router.Use(AuthenticateIDToken(server), GinContextToContextMiddleware(server), FirebaseClientToContextMiddleware(server), FirebaseDBClientToContextMiddleware(server))
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{
		Conf:       *server.Conf,
		Server:     server,
		UserSrvURL: server.Conf.ServiceEndpoints.UserGraphQL,
		// Token:      server.UserSrvToken,
		// TODO Temp workaround
		Client: func() *graphql.Client {
			tokenString, err := server.UserSrvToken.GetTokenString()
			if err != nil {
				panic(err)
			}
			src := oauth2.StaticTokenSource(
				&oauth2.Token{
					AccessToken: tokenString,
					TokenType:   token.TypeJWT,
				},
			)
			httpClient := oauth2.NewClient(context.Background(), src)
			return graphql.NewClient(server.Services.UserGraphQL, graphql.WithHTTPClient(httpClient))
		}(),
	}}))
	v1TokenAuthenticatedWithFirebaseRouter.POST("/graphql/user", gin.WrapH(srv))

	// v0 api proxy every request to the restful serverce
	v0Router := apiRouter.Group("/v0")
	v0tokenStateRouter := v0Router.Use(GetIDTokenOnly(server))
	proxyURL, err := url.Parse(server.Conf.V0RESTfulSrvTargetURL)
	if err != nil {
		return err
	}

	v0tokenStateRouter.Any("/*wildcard", NewSingleHostReverseProxy(proxyURL, v0Router.BasePath()))

	return nil
}
