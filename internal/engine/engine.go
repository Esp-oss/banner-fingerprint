// Package engine 实现"原始 banner -> 指纹"的识别流水线。
//
// 流水线：
//  1. 归一化：base64 解码、字面量 \xNN 还原、BOM 清理、超长截断；
//  2. 预分类：TLS 记录头、MySQL 握手包等二进制签名由规则中的 bytes_hex 处理；
//  3. 规则匹配：按 priority 降序逐条匹配，内容优先，端口只作为置信度先验；
//  4. 打分：取置信度最高者；全不命中返回 unknown。
//
// 该包不感知 HTTP，也不感知 YAML 文件格式，便于单测与复用。
package engine

import (
	"bytes"
	"encoding/base64"
	"math"
	"regexp"
	"strings"

	"github.com/Esp-oss/banner-fingerprint/internal/model"
	"github.com/Esp-oss/banner-fingerprint/internal/rules"
)

// maxBannerBytes 限制参与匹配的 banner 长度，避免超长输入放大 CPU 开销。
const maxBannerBytes = 64 * 1024

// Engine 是并发安全的：规则只读，Identify 无共享可变状态。
type Engine struct {
	rules *rules.Loaded
}

// New 创建识别引擎。
func New(loaded *rules.Loaded) *Engine {
	return &Engine{rules: loaded}
}

// Identify 识别单条原始数据。
// 任何异常输入都只会得到 unknown，不会 panic、不会中断整批处理。
func (e *Engine) Identify(in model.Input) model.Result {
	port := int(in.Port)
	raw := Normalize(in)
	if len(raw) == 0 {
		return model.Unknown(in.IP, port)
	}
	text := string(raw)

	best := -1.0
	result := model.Unknown(in.IP, port)
	for _, rule := range e.rules.Rules {
		if !rule.Matches(raw, text) {
			continue
		}
		product, version, osHint := rule.Extract(text)
		confidence := rule.BaseConfidence
		if rule.PortMatched(port) {
			confidence += rule.PortBonus
		}
		confidence = clamp(confidence)
		if confidence > best {
			best = confidence
			result = model.Result{
				IP:         in.IP,
				Port:       port,
				Protocol:   rule.Protocol,
				Product:    product,
				Version:    version,
				OSHint:     osHint,
				Confidence: math.Round(confidence*100) / 100,
			}
		}
	}
	return result
}

// Normalize 将输入转换为参与匹配的原始字节。
func Normalize(in model.Input) []byte {
	var raw []byte
	if in.BannerBase64 != "" {
		raw = decodeBase64(in.BannerBase64)
	}
	if raw == nil {
		raw = []byte(in.Banner)
	}
	raw = unescapeLiteral(raw)
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	if len(raw) > maxBannerBytes {
		raw = raw[:maxBannerBytes]
	}
	// 只裁剪前导空白：TLS/MySQL 等二进制协议的首字节不是空白，不受影响。
	return bytes.TrimLeft(raw, " \t\r\n")
}

func decodeBase64(s string) []byte {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded
		}
	}
	return nil
}

var hexEscapePattern = regexp.MustCompile(`\\x[0-9A-Fa-f]{2}`)

// unescapeLiteral 处理"扫描器把转义序列原样写进 JSON 字符串"的情况，
// 例如 MySQL 握手包常见的字面量 `J\x00\x00\x00\n8.0.32\x00`。
//
// 只在真正出现 \xNN，或出现字面量 \r\n 且文本中不存在真实换行时才展开，
// 避免把 URL、Windows 路径中的反斜杠误伤为控制字符。
func unescapeLiteral(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\`)) {
		return b
	}
	hasHex := hexEscapePattern.Match(b)
	hasLiteralNewline := bytes.Contains(b, []byte(`\r`)) || bytes.Contains(b, []byte(`\n`))
	hasRealNewline := bytes.ContainsAny(b, "\r\n")
	if !hasHex && !(hasLiteralNewline && !hasRealNewline) {
		return b
	}

	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		switch b[i+1] {
		case 'x':
			if i+3 < len(b) {
				hi, okHi := fromHex(b[i+2])
				lo, okLo := fromHex(b[i+3])
				if okHi && okLo {
					out = append(out, hi<<4|lo)
					i += 3
					continue
				}
			}
			out = append(out, b[i])
		case 'r':
			out = append(out, '\r')
			i++
		case 'n':
			out = append(out, '\n')
			i++
		case 't':
			out = append(out, '\t')
			i++
		case '0':
			out = append(out, 0)
			i++
		case '\\':
			out = append(out, '\\')
			i++
		default:
			out = append(out, b[i])
		}
	}
	return out
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func clamp(confidence float64) float64 {
	if confidence < 0 {
		return 0
	}
	if confidence > 1 {
		return 1
	}
	return confidence
}
