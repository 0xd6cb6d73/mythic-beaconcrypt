package provider

import (
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func configEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"BEACONCRYPT_PROVIDER_NAME", "RABBITMQ_URL", "RABBITMQ_HOST", "RABBITMQ_PORT", "RABBITMQ_USER", "RABBITMQ_PASSWORD", "RABBITMQ_VHOST", "BEACONCRYPT_RPC_TIMEOUT", "BEACONCRYPT_SERVER_KID", "BEACONCRYPT_NAMESPACE", "BEACONCRYPT_STATE_ID", "BEACONCRYPT_MAX_MESSAGE_BYTES", "BEACONCRYPT_MAX_PROFILES", "BEACONCRYPT_MAX_SESSIONS", "BEACONCRYPT_MAX_REQUESTS", "BEACONCRYPT_RESULT_RETENTION_SECONDS"} {
		t.Setenv(name, "")
	}
	t.Setenv("RABBITMQ_URL", "amqp://test:password@127.0.0.1:5672/mythic_vhost")
}

func TestLoadConfigCampaignDefaults(t *testing.T) {
	configEnvironment(t)
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Service.Name != "beaconcrypt" || config.Service.RPCTimeout != 20*time.Second || config.Engine.Initialize || config.Engine.Namespace != "beaconcrypt" || config.Engine.StateID != "server" || config.Engine.MaxMessageBytes != 1<<20 || config.Engine.MaxProfiles != 1000 || config.Engine.MaxSessions != 1000 || config.Engine.MaxRequests != 5000 || config.Engine.ResultRetentionSeconds != 86400 {
		t.Fatalf("unexpected defaults: %#v", config)
	}
}

func TestLoadConfigEscapesBrokerCredentialsAndVirtualHost(t *testing.T) {
	configEnvironment(t)
	t.Setenv("RABBITMQ_URL", "")
	t.Setenv("RABBITMQ_HOST", "::1")
	t.Setenv("RABBITMQ_PORT", "5673")
	t.Setenv("RABBITMQ_USER", "provider@mythic")
	t.Setenv("RABBITMQ_PASSWORD", "p@ss:/?#%word")
	t.Setenv("RABBITMQ_VHOST", "test space")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(config.Service.AMQPURL)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := parsed.User.Password()
	if parsed.Hostname() != "::1" || parsed.Port() != "5673" || parsed.User.Username() != "provider@mythic" || password != "p@ss:/?#%word" || parsed.Path != "/test space" {
		t.Fatal("broker URL changed credentials, host, or virtual host")
	}
}

func TestLoadConfigRejectsInvalidInputWithoutDisclosingSecrets(t *testing.T) {
	for _, test := range []struct{ name, value string }{
		{"BEACONCRYPT_MAX_MESSAGE_BYTES", "8388609"},
		{"RABBITMQ_URL", "amqps://user:secret@example.test"},
		{"BEACONCRYPT_PROVIDER_NAME", "bad:name"}, {"BEACONCRYPT_PROVIDER_NAME", "bad name"}, {"RABBITMQ_URL", "https://user:secret@example.test"}, {"RABBITMQ_URL", "amqp:///missing-host"}, {"BEACONCRYPT_RPC_TIMEOUT", "999ms"}, {"BEACONCRYPT_RPC_TIMEOUT", "31s"}, {"BEACONCRYPT_RPC_TIMEOUT", "6m"}, {"BEACONCRYPT_RPC_TIMEOUT", "invalid"}, {"BEACONCRYPT_SERVER_KID", "-1"}, {"BEACONCRYPT_SERVER_KID", "18446744073709551616"}, {"BEACONCRYPT_MAX_MESSAGE_BYTES", "0"}, {"BEACONCRYPT_MAX_PROFILES", "-1"}, {"BEACONCRYPT_MAX_SESSIONS", "invalid"}, {"BEACONCRYPT_MAX_REQUESTS", "0"}, {"BEACONCRYPT_RESULT_RETENTION_SECONDS", "-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configEnvironment(t)
			t.Setenv(test.name, test.value)
			_, err := LoadConfig()
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "user:secret") {
				t.Fatal("configuration error disclosed deployment credentials")
			}
		})
	}
}

func TestLoadConfigOwnsBeaconcryptMetadataAndLimits(t *testing.T) {
	configEnvironment(t)
	overrides := map[string]string{
		"BEACONCRYPT_PROVIDER_NAME": "custom-beaconcrypt", "BEACONCRYPT_RPC_TIMEOUT": "3s",
		"BEACONCRYPT_SERVER_KID": "18446744073709551615", "BEACONCRYPT_NAMESPACE": "custom_namespace", "BEACONCRYPT_STATE_ID": "custom/state",
		"BEACONCRYPT_MAX_MESSAGE_BYTES": "8192", "BEACONCRYPT_MAX_PROFILES": "101", "BEACONCRYPT_MAX_SESSIONS": "102", "BEACONCRYPT_MAX_REQUESTS": "103", "BEACONCRYPT_RESULT_RETENTION_SECONDS": "3600",
	}
	for name, value := range overrides {
		t.Setenv(name, value)
	}
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Service.Name != "custom-beaconcrypt" || config.Service.RPCTimeout != 3*time.Second || config.Service.Version != Version || config.Service.Description != "Beaconcrypt cryptographic provider" || config.Engine.ServerKID != ^uint64(0) || config.Engine.Namespace != "custom_namespace" || config.Engine.StateID != "custom/state" || config.Engine.MaxMessageBytes != 8192 || config.Engine.MaxProfiles != 101 || config.Engine.MaxSessions != 102 || config.Engine.MaxRequests != 103 || config.Engine.ResultRetentionSeconds != 3600 {
		t.Fatalf("Beaconcrypt configuration changed: %#v", config)
	}
	expected := wire.Capabilities{APIVersion: wire.APIVersion, Schemes: []string{"beaconcrypt"}, Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: config.Engine.MaxMessageBytes, ResultRetentionSeconds: config.Engine.ResultRetentionSeconds}
	if !reflect.DeepEqual(config.Service.Capabilities, expected) {
		t.Fatalf("runtime capabilities differ from protocol configuration: %#v", config.Service.Capabilities)
	}
}
