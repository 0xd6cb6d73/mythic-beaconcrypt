package service

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func configEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"EXAMPLE_PROVIDER_NAME", "EXAMPLE_RPC_TIMEOUT", "OTHER_PROVIDER_NAME", "OTHER_RPC_TIMEOUT", "RABBITMQ_URL", "RABBITMQ_HOST", "RABBITMQ_PORT", "RABBITMQ_USER", "RABBITMQ_PASSWORD", "RABBITMQ_VHOST"} {
		t.Setenv(name, "")
	}
	t.Setenv("RABBITMQ_URL", "amqp://test:password@127.0.0.1:5672/mythic_vhost")
}

func TestLoadConfigDefaultsAndProviderPrefix(t *testing.T) {
	configEnvironment(t)
	t.Setenv("OTHER_PROVIDER_NAME", "unrelated")
	t.Setenv("OTHER_RPC_TIMEOUT", "1s")
	config, err := LoadConfig("example", "EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "example" || config.RPCTimeout != 20*time.Second || config.Description != "" || config.Version != "" || len(config.Capabilities.Schemes) != 0 {
		t.Fatalf("transport defaults included provider-specific configuration: %#v", config)
	}
	t.Setenv("EXAMPLE_PROVIDER_NAME", "custom-provider")
	t.Setenv("EXAMPLE_RPC_TIMEOUT", "3s")
	config, err = LoadConfig("example", "EXAMPLE")
	if err != nil || config.Name != "custom-provider" || config.RPCTimeout != 3*time.Second {
		t.Fatalf("provider prefix was ignored: %#v, %v", config, err)
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
	config, err := LoadConfig("example", "EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(config.AMQPURL)
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
		{"EXAMPLE_PROVIDER_NAME", "bad:name"}, {"EXAMPLE_PROVIDER_NAME", "bad name"},
		{"RABBITMQ_URL", "amqps://user:secret@example.test"},
		{"RABBITMQ_URL", "https://user:secret@example.test"},
		{"RABBITMQ_URL", "amqp:///missing-host"},
		{"EXAMPLE_RPC_TIMEOUT", "999ms"}, {"EXAMPLE_RPC_TIMEOUT", "31s"}, {"EXAMPLE_RPC_TIMEOUT", "invalid"},
	} {
		t.Run(test.name+"="+test.value, func(t *testing.T) {
			configEnvironment(t)
			t.Setenv(test.name, test.value)
			_, err := LoadConfig("example", "EXAMPLE")
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "user:secret") {
				t.Fatal("configuration error disclosed deployment credentials")
			}
		})
	}
}

func TestLoadConfigRequiresBrokerCredentials(t *testing.T) {
	configEnvironment(t)
	t.Setenv("RABBITMQ_URL", "")
	if _, err := LoadConfig("example", "EXAMPLE"); err == nil {
		t.Fatal("missing broker credentials accepted")
	}
}
