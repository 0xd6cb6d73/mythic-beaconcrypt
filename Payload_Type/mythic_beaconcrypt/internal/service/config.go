package service

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

type Config struct {
	Name         string
	AMQPURL      string
	RPCTimeout   time.Duration
	Description  string
	Version      string
	Capabilities wire.Capabilities
}

// LoadConfig reads transport settings shared by crypto providers. Protocol
// configuration, metadata, and capabilities belong to the provider package.
func LoadConfig(defaultName, envPrefix string) (Config, error) {
	name := env(envPrefix+"_PROVIDER_NAME", defaultName)
	if _, err := wire.RoutingKey(name); err != nil {
		return Config{}, fmt.Errorf("invalid %s_PROVIDER_NAME", envPrefix)
	}
	address := os.Getenv("RABBITMQ_URL")
	if address == "" {
		password := os.Getenv("RABBITMQ_PASSWORD")
		if password == "" {
			return Config{}, errors.New("RABBITMQ_PASSWORD or RABBITMQ_URL is required")
		}
		u := url.URL{Scheme: "amqp", Host: net.JoinHostPort(env("RABBITMQ_HOST", "mythic_rabbitmq"), env("RABBITMQ_PORT", "5672")), Path: "/" + env("RABBITMQ_VHOST", "mythic_vhost"), User: url.UserPassword(env("RABBITMQ_USER", "mythic_user"), password)}
		address = u.String()
	}
	u, err := url.Parse(address)
	if err == nil && u.Scheme == "amqps" {
		return Config{}, errors.New("the pinned MythicContainer SDK does not support AMQPS")
	}
	if err != nil || u.Scheme != "amqp" || u.Hostname() == "" {
		return Config{}, errors.New("invalid RABBITMQ_URL")
	}
	timeout, err := time.ParseDuration(env(envPrefix+"_RPC_TIMEOUT", "20s"))
	if err != nil || timeout < time.Second || timeout > 30*time.Second {
		return Config{}, fmt.Errorf("%s_RPC_TIMEOUT must be between 1s and 30s", envPrefix)
	}
	return Config{Name: name, AMQPURL: address, RPCTimeout: timeout}, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
