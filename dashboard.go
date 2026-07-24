package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func dashboardLogPath(name string) string {
	switch name {
	case "result":
		return RESULT_FILE
	case "summary":
		return REBOOT_LOG
	case "lspci":
		return LPOTSCAN_LOG
	case "config_space":
		return CONFIG_CHANGES_LOG
	default:
		return ""
	}
}

func startDashboard() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	})
	mux.HandleFunc("/api/result", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		data, err := os.ReadFile(RESULT_FILE)
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"status":"EMPTY","message":"No LPOT result is available. Run a normal test with -t first."}`)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		path := dashboardLogPath(r.URL.Query().Get("name"))
		if path == "" {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if r.URL.Query().Get("name") == "result" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Write(data)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start dashboard listener: %w", err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	url := "http://" + listener.Addr().String()
	fmt.Printf("LPOT dashboard listening at %s\n", url)
	go openDashboardBrowser(url)
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(listener) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("dashboard server stopped: %w", err)
	}
}

func openDashboardBrowser(url string) {
	for _, path := range []string{"/usr/bin/xdg-open", "/bin/xdg-open"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, path, url).Run()
		cancel()
		if err == nil {
			return
		}
	}
	fmt.Fprintln(os.Stderr, "Suggestion: open the dashboard URL manually because xdg-open was unavailable or failed.")
}
