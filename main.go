/*
Fox3 is a post-exploitation command and control framework.

This file is part of Fox3.
Copyright (C) 2024 Russel Van Tuyl

Fox3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Fox3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Fox3.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	// Standard
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Internal
	fox3 "github.com/nzyuko/fox3/v2/pkg"
	"github.com/nzyuko/fox3/v2/pkg/db"
	"github.com/nzyuko/fox3/v2/pkg/logging"
	"github.com/nzyuko/fox3/v2/pkg/services/rest"
)

func main() {
	password := flag.String("password", "fox3", "password for the REST API and agent listeners")
	restAddr := flag.String("rest", "0.0.0.0:8080", "address the REST API + WebSocket server binds to")
	debug := flag.Bool("debug", false, "enable debug logging")
	trace := flag.Bool("trace", false, "enable trace logging")
	extra := flag.Bool("extra", false, "enable extra-debug logging (dumps HTTP headers per connection)")
	v := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *v {
		fmt.Printf("Fox3 Version: %s, Build: %s\n", fox3.Version, fox3.Build)
		return
	}

	// Set the logging level
	if *extra {
		logging.SetLevel(logging.LevelExtraDebug)
	} else if *trace {
		logging.SetLevel(logging.LevelTrace)
	} else if *debug {
		logging.SetLevel(logging.LevelDebug)
	}

	// Initialize database
	db.InitDB()
	db.AutoMigrate()

	// Warn about default password
	if *password == "fox3" {
		slog.Warn("Using default password — change with --password for production use")
	}

	// Start REST API + WebSocket server
	restServer := rest.NewRestServer(*password)
	go func() {
		slog.Info("Starting REST API server", "addr", *restAddr)
		if err := restServer.Run(*restAddr); err != nil {
			slog.Error("REST server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	slog.Info("Received signal, shutting down", "signal", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := restServer.Shutdown(ctx); err != nil {
		slog.Error("REST shutdown error", "error", err)
	}

	log.Printf("Exiting")
}
