package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/provider"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/service"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/storage"
)

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional argument")
	}
	config, err := provider.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx, config.Service, func(store storage.Store) (service.Backend, error) {
		return provider.New(config, store)
	}); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
