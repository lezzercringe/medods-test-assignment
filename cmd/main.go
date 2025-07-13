package main

import (
	"assignment/api"
	"assignment/auth"
	"assignment/bcrypt"
	"assignment/clock"
	"assignment/config"
	"assignment/jwt"
	"assignment/postgres"
	"assignment/webhook"
	"bytes"
	"context"
	"flag"
	"os"

	_ "assignment/docs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"
	echoSwagger "github.com/swaggo/echo-swagger"
)

//	@title		Auth Service API
//	@version	1.0

//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Format: Bearer <token>

func main() {
	var configPath string
	flag.StringVar(&configPath, "config_path", "config.yaml", "./config.yaml")
	flag.Parse()

	cfgFile, err := os.ReadFile(configPath)
	if err != nil {
		logrus.WithField("config_path", configPath).WithError(err).
			Fatal("Could not open config file")
	}
	cfg := config.MustReadConfig(bytes.NewBuffer(cfgFile))

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Postgres.ConnString)
	if err != nil {
		logrus.WithError(err).Fatal("Could not init postgres conn pool")
	}
	defer pool.Close()

	clock := &clock.STDClock{}

	whNotifier := webhook.NewNotifier(webhook.NotifierCfg{
		Retries: cfg.IPWebhook.Retries,
		Timeout: cfg.IPWebhook.Timeout,
		URL:     cfg.IPWebhook.URL,
	})
	hashService := bcrypt.NewHashService()
	sessionRepository := postgres.NewSessionRepository(pool)
	revocationList := postgres.NewRevocationList(pool)
	tokenService := jwt.NewTokenService(clock, []byte(cfg.JWT.Secret))

	authCfg := auth.Config{
		AccessTokenTTL:  cfg.JWT.AccessTTL,
		RefreshTokenTTL: cfg.JWT.RefreshTTL,
	}

	authService := auth.NewService(
		authCfg,
		clock,
		sessionRepository,
		tokenService,
		revocationList,
		whNotifier,
		hashService,
	)

	authMw := api.NewAuthorizationMw(authService)

	e := echo.New()
	e.Logger.SetOutput(logrus.StandardLogger().Writer())
	e.IPExtractor = echo.ExtractIPDirect()

	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.ContextTimeout(cfg.API.RequestTimeout))
	e.Use(api.HandleErrors)

	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.POST("/auth/login", api.NewLoginHandler(authService).Handle)
	e.POST("/auth/refresh", api.NewRefreshHandler(authService).Handle)
	e.POST("/auth/logout", api.NewLogoutHandler(authService).Handle, authMw.AuthorizeRequest)
	e.GET("/user", api.NewUserHandler().Handle, authMw.AuthorizeRequest)

	logrus.WithError(e.Start(cfg.API.Addr)).Fatal("Server stopped")
}
