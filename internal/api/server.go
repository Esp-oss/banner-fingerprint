// Package api：HTTP 处理层。
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/Esp-oss/banner-fingerprint/internal/engine"
	"github.com/Esp-oss/banner-fingerprint/internal/model"
	"github.com/Esp-oss/banner-fingerprint/internal/rules"
)

const maxBodyBytes = 8 << 20 // 8 MiB，批量场景足够且能防止内存打满

// Server 组合识别引擎与元信息，暴露 HTTP Handler。
type Server struct {
	engine  *engine.Engine
	rules   *rules.Loaded
	version string
	started time.Time
	logger  *slog.Logger
}

// New 创建 API 服务。
func New(eng *engine.Engine, loaded *rules.Loaded, version string, logger *slog.Logger) *Server {
	return &Server{
		engine:  eng,
		rules:   loaded,
		version: version,
		started: time.Now(),
		logger:  logger,
	}
}

// Handler 返回带中间件的路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/fingerprint", s.handleFingerprint)
	mux.HandleFunc("/health", s.handleHealth)
	return s.recoverer(s.accessLog(s.withRequestID(mux)))
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}

	started := time.Now()
	body, err := readLimited(w, r, maxBodyBytes)
	if err != nil {
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", err.Error())
		return
	}
	inputs, err := ParseInputs(body)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	results := make([]model.Result, 0, len(inputs))
	identified := 0
	for _, input := range inputs {
		result := s.engine.Identify(input)
		if result.Protocol != "unknown" {
			identified++
		}
		results = append(results, result)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Total-Count", strconv.Itoa(len(results)))
	w.Header().Set("X-Identified-Count", strconv.Itoa(identified))
	w.Header().Set("X-Elapsed-Ms", strconv.FormatInt(time.Since(started).Milliseconds(), 10))
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is supported")
		return
	}
	payload := struct {
		Status  string  `json:"status"`
		Version string  `json:"version"`
		UptimeS float64 `json:"uptime_s"`
		Rules   struct {
			Files  int    `json:"files"`
			Loaded int    `json:"loaded"`
			Source string `json:"source"`
		} `json:"rules"`
	}{
		Status:  "ok",
		Version: s.version,
		UptimeS: time.Since(s.started).Seconds(),
	}
	payload.Rules.Files = s.rules.Files
	payload.Rules.Loaded = len(s.rules.Rules)
	payload.Rules.Source = s.rules.Source

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}

// ---- 中间件 ----

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic recovered",
					"request_id", requestID(r),
					"panic", recovered,
					"stack", string(debug.Stack()),
				)
				s.writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			var buf [8]byte
			_, _ = rand.Read(buf[:])
			id = hex.EncodeToString(buf[:])
		}
		w.Header().Set("X-Request-ID", id)
		r.Header.Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.logger.Info("http_request",
			"request_id", requestID(r),
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"bytes", recorder.bytes,
			"duration_ms", time.Since(started).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func requestID(r *http.Request) string {
	return r.Header.Get("X-Request-ID")
}

func readLimited(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	reader := http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("request body exceeds %d bytes", limit)
	}
	return data, nil
}

// ---- 错误契约 ----

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: errorBody{
		Code:      code,
		Message:   message,
		RequestID: requestID(r),
	}})
}
