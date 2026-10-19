// Package api 提供 HTTP 接入层：请求解析、响应编码、错误契约与中间件。
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Esp-oss/banner-fingerprint/internal/model"
)

var envelopeKeys = []string{"records", "items", "data", "inputs", "results"}

// ParseInputs 解析批量请求体，兼容下列形态：
//  1. 裸数组：[{"ip":...}, ...]（题面契约）
//  2. 包一层：{"records":[...]} / items / data / inputs / results
//  3. 单条记录：{"ip":..., "banner":...}
//  4. 双层编码的 JSON 字符串："[{\"ip\":...}]"
//
// 同时修复非法的 \xNN 转义（部分扫描器会原样输出），并保留 \\xNN 的语义。
func ParseInputs(body []byte) ([]model.Input, error) {
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	body = repairInvalidHexEscapes(body)

	// 最多解包 3 层（数组/包装对象/JSON 字符串），防止恶意嵌套。
	for depth := 0; depth < 3; depth++ {
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 {
			return nil, errors.New("empty request body")
		}

		switch trimmed[0] {
		case '[':
			var list []model.Input
			if err := json.Unmarshal(trimmed, &list); err != nil {
				return nil, fmt.Errorf("invalid JSON array: %w", err)
			}
			return list, nil

		case '{':
			var probe map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &probe); err != nil {
				return nil, fmt.Errorf("invalid JSON object: %w", err)
			}
			var nested []byte
			for _, key := range envelopeKeys {
				if raw, ok := probe[key]; ok {
					nested = raw
					break
				}
			}
			if nested != nil {
				body = nested
				continue
			}
			// 单条记录：允许但不作为批量契约的推荐形态。
			if _, ok := probe["banner"]; ok {
				var one model.Input
				if err := json.Unmarshal(trimmed, &one); err != nil {
					return nil, fmt.Errorf("invalid JSON record: %w", err)
				}
				return []model.Input{one}, nil
			}
			if _, ok := probe["ip"]; ok {
				var one model.Input
				if err := json.Unmarshal(trimmed, &one); err != nil {
					return nil, fmt.Errorf("invalid JSON record: %w", err)
				}
				return []model.Input{one}, nil
			}
			return nil, errors.New(`unsupported JSON object: expected an array or a {"records": [...]} wrapper`)

		case '"':
			// 兼容请求体被整体 JSON 编码成字符串的情况。
			var encoded string
			if err := json.Unmarshal(trimmed, &encoded); err != nil {
				return nil, fmt.Errorf("invalid JSON string: %w", err)
			}
			body = []byte(encoded)
			continue

		default:
			return nil, fmt.Errorf("invalid JSON: unexpected leading byte %q", trimmed[0])
		}
	}
	return nil, errors.New("JSON nesting is too deep")
}

// repairInvalidHexEscapes 把 JSON 中非法的 \xNN 转义替换为等价的 \u00NN。
// 反斜杠数量为偶数时（\\xNN）属于合法转义，保持原样，交由 engine 的字面量还原处理。
func repairInvalidHexEscapes(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\x`)) {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			out = append(out, b[i])
			continue
		}
		j := i
		for j < len(b) && b[j] == '\\' {
			j++
		}
		run := j - i
		if run%2 == 1 && j+2 < len(b) && b[j] == 'x' && isHex(b[j+1]) && isHex(b[j+2]) {
			out = append(out, b[i:j-1]...) // 前 n-1 个反斜杠
			out = append(out, '\\', 'u', '0', '0', b[j+1], b[j+2])
			i = j + 2
			continue
		}
		out = append(out, b[i:j]...)
		i = j - 1
	}
	return out
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
