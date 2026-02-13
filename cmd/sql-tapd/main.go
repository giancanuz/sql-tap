package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/mickamy/sql-tap/broker"
	"github.com/mickamy/sql-tap/dsn"
	"github.com/mickamy/sql-tap/explain"
	"github.com/mickamy/sql-tap/proxy"
	"github.com/mickamy/sql-tap/proxy/postgres"
	"github.com/mickamy/sql-tap/server"
)

var version = "dev"

func main() {
	fs := flag.NewFlagSet("sql-tapd", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "sql-tapd — SQL proxy daemon for sql-tap\n\nUsage:\n  sql-tapd [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n  DATABASE_URL    DSN for EXPLAIN queries (read by default via -dsn-env)\n")
	}

	driver := fs.String("driver", "postgres", "database driver: postgres")
	listen := fs.String("listen", ":5433", "client listen address")
	upstream := fs.String("upstream", "localhost:5432", "upstream database address")
	grpcAddr := fs.String("grpc", ":9091", "gRPC server address for TUI")
	dsnEnv := fs.String("dsn-env", "DATABASE_URL", "environment variable holding DSN for EXPLAIN")
	showVersion := fs.Bool("version", false, "show version and exit")

	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("sql-tapd %s\n", version)
		return
	}

	if err := run(*driver, *listen, *upstream, *grpcAddr, *dsnEnv); err != nil {
		log.Fatal(err)
	}
}

func run(driver, listen, upstream, grpcAddr, dsnEnv string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Broker
	b := broker.New(256)

	// EXPLAIN client (optional)
	var explainClient *explain.Client
	if raw := os.Getenv(dsnEnv); raw != "" {
		db, err := dsn.Open(raw)
		if err != nil {
			return fmt.Errorf("open db for explain: %w", err)
		}
		explainClient = explain.NewClient(db)
		defer func() { _ = explainClient.Close() }()
		log.Printf("EXPLAIN enabled")
	} else {
		log.Printf("EXPLAIN disabled (%s not set)", dsnEnv)
	}

	// gRPC server
	var lc net.ListenConfig
	grpcLis, err := lc.Listen(ctx, "tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("listen grpc %s: %w", grpcAddr, err)
	}
	srv := server.New(b, explainClient)
	go func() {
		log.Printf("gRPC server listening on %s", grpcAddr)
		if err := srv.Serve(grpcLis); err != nil {
			log.Printf("grpc serve: %v", err)
		}
	}()

	// Proxy
	var p proxy.Proxy
	switch driver {
	case "postgres":
		p = postgres.New(listen, upstream)
	case "mysql":
		return errors.New("mysql driver is not yet supported (coming soon)")
	default:
		return fmt.Errorf("unsupported driver: %s", driver)
	}

	go func() {
		for ev := range p.Events() {
			b.Publish(ev)
		}
	}()

	log.Printf("proxying %s -> %s (driver=%s)", listen, upstream, driver)
	if err := p.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}

	srv.GracefulStop()
	return nil
}
