// Package provider composes the Beaconcrypt protocol with the generic Mythic runtime.
package provider

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/service"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

const Version = "0.3.0"

type Config struct {
	Service service.Config
	Engine  engine.Config
}

func LoadConfig() (Config, error) {
	runtime, err := service.LoadConfig("beaconcrypt", "BEACONCRYPT")
	if err != nil {
		return Config{}, err
	}
	kid, err := strconv.ParseUint(env("BEACONCRYPT_SERVER_KID", "0"), 10, 64)
	if err != nil {
		return Config{}, errors.New("invalid BEACONCRYPT_SERVER_KID")
	}
	limits := map[string]struct {
		fallback int
		target   *int
	}{}
	config := Config{Service: runtime, Engine: engine.Config{
		Namespace: env("BEACONCRYPT_NAMESPACE", "beaconcrypt"), StateID: env("BEACONCRYPT_STATE_ID", "server"), ServerKID: kid,
	}}
	limits["BEACONCRYPT_MAX_MESSAGE_BYTES"] = struct {
		fallback int
		target   *int
	}{1 << 20, &config.Engine.MaxMessageBytes}
	limits["BEACONCRYPT_MAX_PROFILES"] = struct {
		fallback int
		target   *int
	}{1000, &config.Engine.MaxProfiles}
	limits["BEACONCRYPT_MAX_SESSIONS"] = struct {
		fallback int
		target   *int
	}{1000, &config.Engine.MaxSessions}
	limits["BEACONCRYPT_MAX_REQUESTS"] = struct {
		fallback int
		target   *int
	}{5000, &config.Engine.MaxRequests}
	limits["BEACONCRYPT_RESULT_RETENTION_SECONDS"] = struct {
		fallback int
		target   *int
	}{86400, &config.Engine.ResultRetentionSeconds}
	for name, limit := range limits {
		value, err := strconv.Atoi(env(name, strconv.Itoa(limit.fallback)))
		if err != nil || value <= 0 {
			return Config{}, fmt.Errorf("%s must be a positive integer", name)
		}
		*limit.target = value
	}
	if config.Engine.MaxMessageBytes > engine.MaxProviderMessageBytes {
		return Config{}, errors.New("BEACONCRYPT_MAX_MESSAGE_BYTES must not exceed 8 MiB")
	}
	config.Service.Description = "Beaconcrypt cryptographic provider"
	config.Service.Version = Version
	config.Service.Capabilities = wire.Capabilities{APIVersion: wire.APIVersion, Schemes: []string{engine.Scheme}, Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: config.Engine.MaxMessageBytes, ResultRetentionSeconds: config.Engine.ResultRetentionSeconds}
	return config, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
