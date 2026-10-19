// Package model 定义系统对外契约的数据结构。
// 该包不依赖任何业务逻辑，server 与 client 共用同一份结构，避免契约漂移。
package model

import (
	"strconv"
	"strings"
)

// Input 是一条网络扫描原始数据。
// Banner 与 BannerBase64 二选一：二进制 banner（如 MySQL 握手包、TLS 记录）
// 建议使用 BannerBase64，避免 JSON 转义带来的信息损失。
type Input struct {
	IP           string  `json:"ip"`
	Port         FlexInt `json:"port"`
	Banner       string  `json:"banner"`
	BannerBase64 string  `json:"banner_base64,omitempty"`
}

// FlexInt 兼容 port 以数字或字符串形式出现（"22" 与 22 均可）。
// 无法解析时归零而不是让整批请求失败：单条数据的质量问题不应影响批量识别。
type FlexInt int

// UnmarshalJSON 实现宽松的整数解析。
func (f *FlexInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		*f = 0
		return nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		*f = FlexInt(n)
		return nil
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		*f = FlexInt(int(v))
		return nil
	}
	*f = 0
	return nil
}

// Result 是一条识别结果。
// Protocol 为 unknown 时表示无法识别，而不是处理失败。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Unknown 构造一条未识别结果，保证字段类型稳定（空串而非 null）。
func Unknown(ip string, port int) Result {
	return Result{
		IP:         ip,
		Port:       port,
		Protocol:   "unknown",
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}
}
