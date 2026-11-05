package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charlesfeval/caddy-auth/internal/authsvc"
)

func main() {
	dbPath := env("CADDY_AUTH_DB", "caddy-auth.db")
	listen := env("CADDY_AUTH_LISTEN", "127.0.0.1:8090")
	key := os.Getenv("CADDY_AUTH_INSTANCE_TOKEN")
	store, err := authsvc.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	service, err := authsvc.NewServer(store, key)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: listen, Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := store.Cleanup(); err != nil {
					log.Printf("authentication cleanup failed: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("auth service listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
