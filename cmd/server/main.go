// Command server 启动 Banner 指纹识别 HTTP 服务。
//
// 生产化要点：
//   - 配置全部来自环境变量/命令行，无硬编码；
//   - 规则加载失败立即退出（fail fast）；
//   - 只暴露 /fingerprint 与 /health；
//   - 平滑退出，配合容器编排的 stop_grace_period；
//   - 内置 -healthcheck 子命令，供 scratch 镜像的 Docker HEALTHCHECK 使用。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Esp-oss/banner-fingerprint/internal/api"
	"github.com/Esp-oss/banner-fingerprint/internal/engine"
	"github.com/Esp-oss/banner-fingerprint/internal/rules"
)

// version 由构建参数注入：-ldflags "-X main.version=1.0.0"
var version = "dev"

func main() {
	addr := flag.String("addr", env("HTTP_ADDR", ":8080"), "HTTP listen address")
	rulesDir := flag.String("rules", env("RULES_DIR", "./rules"), "directory containing YAML rules")
	healthcheck := flag.Bool("healthcheck", false, "run one health probe and exit (used by Docker HEALTHCHECK)")
	healthURL := flag.String("healthcheck-url", env("HEALTHCHECK_URL", "http://127.0.0.1:8080/health"), "health probe URL")
	flag.Parse()

	if *healthcheck {
		os.Exit(probe(*healthURL))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	loaded, err := rules.Load(*rulesDir)
	if err != nil {
		logger.Error("load rules failed", "error", err)
		os.Exit(1)
	}
	logger.Info("rules loaded", "files", loaded.Files, "rules", len(loaded.Rules), "source", loaded.Source)

	handler := api.New(engine.New(loaded), loaded, version, logger).Handler()
	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		logger.Info("server listening", "addr", *addr, "version", version)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("stopped")
}

func probe(url string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: unexpected status", resp.StatusCode)
		return 1
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || payload.Status != "ok" {
		fmt.Fprintln(os.Stderr, "healthcheck: invalid payload")
		return 1
	}
	return 0
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
