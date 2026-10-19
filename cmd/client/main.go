// Command client 是独立的批量识别客户端：
// 读取本地 JSON -> 调用 server -> 表格展示并可选落盘结果。
//
// 退出码约定：
//
//	0 成功
//	2 服务不可达或返回非 200
//	3 输入文件不可读或不是合法 JSON
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Esp-oss/banner-fingerprint/internal/model"
)

func main() {
	input := flag.String("in", "testdata/input.json", "path to the input JSON file")
	server := flag.String("server", env("FINGERPRINT_SERVER", "http://127.0.0.1:7070"), "fingerprint server base URL")
	output := flag.String("out", "", "optional path to write results as JSON")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()

	body, err := os.ReadFile(*input)
	if err != nil {
		fatal(3, "read input: %v", err)
	}
	if !json.Valid(body) {
		fatal(3, "input is not valid JSON: %s", *input)
	}

	endpoint := strings.TrimRight(*server, "/") + "/fingerprint"
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		fatal(2, "build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "banner-fingerprint-client/1.0")

	resp, err := (&http.Client{Timeout: *timeout}).Do(req)
	if err != nil {
		fatal(2, "request %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		fatal(2, "read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatal(2, "server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var results []model.Result
	if err := json.Unmarshal(respBody, &results); err != nil {
		fatal(2, "decode response: %v", err)
	}

	printTable(results)
	if *output != "" {
		pretty, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fatal(2, "encode results: %v", err)
		}
		if err := os.WriteFile(*output, append(pretty, '\n'), 0o644); err != nil {
			fatal(2, "write %s: %v", *output, err)
		}
		fmt.Printf("results written to %s\n", *output)
	}
}

func printTable(results []model.Result) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, result := range results {
		fmt.Fprintf(writer, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			result.IP, result.Port, result.Protocol,
			orDash(result.Product), orDash(result.Version),
			orDash(result.OSHint), result.Confidence)
	}
	_ = writer.Flush()

	identified := 0
	for _, result := range results {
		if result.Protocol != "unknown" {
			identified++
		}
	}
	fmt.Printf("\ntotal=%d identified=%d unknown=%d\n", len(results), identified, len(results)-identified)
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatal(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "client: "+format+"\n", args...)
	os.Exit(code)
}
