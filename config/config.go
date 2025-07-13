package config

import (
	"io"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	API struct {
		Addr           string        `yaml:"addr" validate:"required"`
		RequestTimeout time.Duration `yaml:"timeout"`
	} `yaml:"api"`
	Postgres struct {
		ConnString string `yaml:"conn_string" validate:"required"`
	} `yaml:"postgres"`
	JWT struct {
		AccessTTL  time.Duration `yaml:"access_ttl" validate:"required,gt=0"`
		RefreshTTL time.Duration `yaml:"refresh_ttl" validate:"required,gt=0"`
		Secret     string        `yaml:"secret" validate:"required,min=8"`
	} `yaml:"jwt"`
	IPWebhook struct {
		URL     string        `yaml:"url" validate:"required,url"`
		Retries uint          `yaml:"retries" validate:"gte=0,lte=10"`
		Timeout time.Duration `yaml:"timeout" validate:"required,gt=0"`
	} `yaml:"ip_webhook"`
}

func MustReadConfig(r io.Reader) Config {
	var cfg Config
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil {
		logrus.WithError(err).Panic("Failure decoding app config")
	}

	if err := validator.New().Struct(cfg); err != nil {
		logrus.WithError(err).Panic("Invalid app configuration")
	}

	return cfg
}
