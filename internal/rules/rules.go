// Package rules 负责加载、校验并编译声明式指纹规则。
//
// 设计目标：识别规则与程序代码完全解耦。
//   - 规则以 YAML 描述，新增指纹只需增加/修改文件，无需改动 Go 代码；
//   - 规则目录由 RULES_DIR 指定，容器中以只读卷挂载，可在不重建镜像的情况下替换；
//   - 规则在启动时一次性校验并编译为正则，运行期零反射、零重新解析；
//   - 任一规则非法则启动失败（fail fast），避免带病运行产生静默误判。
package rules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Set 是单个 YAML 规则文件的顶层结构。
type Set struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Rule 是一条指纹规则。
type Rule struct {
	ID             string   `yaml:"id"`
	Priority       int      `yaml:"priority"`
	Protocol       string   `yaml:"protocol"`
	Product        string   `yaml:"product"`
	Ports          []int    `yaml:"ports"`
	Match          Match    `yaml:"match"`
	OSHints        []OSHint `yaml:"os_hint"`
	BaseConfidence float64  `yaml:"base_confidence"`
	PortBonus      float64  `yaml:"port_bonus"`

	// 编译产物，不参与序列化。
	re       *regexp.Regexp
	osRes    []*regexp.Regexp
	hexBytes []byte
}

// Match 描述匹配方式：
//   - regex：Go RE2 正则，支持命名捕获组 version/product；
//   - prefix：文本前缀；
//   - contains：文本包含；
//   - bytes_hex：原始字节前缀（十六进制），用于 TLS/MySQL 等二进制协议。
type Match struct {
	Type    string `yaml:"type"`
	Pattern string `yaml:"pattern"`
}

// OSHint 描述从 banner 中提取操作系统线索的规则。
type OSHint struct {
	Pattern string `yaml:"pattern"`
	Value   string `yaml:"value"`
}

// Loaded 是加载完成后的规则集合。
type Loaded struct {
	Rules  []*Rule
	Files  int
	Source string
}

// Load 读取目录下全部 .yaml/.yml 规则文件。
// 规则按 priority 降序排列；同分时保持文件内声明顺序，保证结果可复现。
func Load(dir string) (*Loaded, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %q: %w", dir, err)
	}

	var all []*Rule
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rule file %q: %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true) // 拼错的字段直接报错，避免规则"看似生效实则被忽略"
		var set Set
		if err := dec.Decode(&set); err != nil {
			return nil, fmt.Errorf("parse rule file %q: %w", path, err)
		}
		for i := range set.Rules {
			rule := &set.Rules[i]
			if err := rule.prepare(); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			all = append(all, rule)
		}
		files++
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no rules loaded from %q", dir)
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].Priority > all[j].Priority })
	return &Loaded{Rules: all, Files: files, Source: dir}, nil
}

func (r *Rule) prepare() error {
	if r.ID == "" {
		return fmt.Errorf("rule id is required")
	}
	if r.Protocol == "" {
		return fmt.Errorf("rule %q: protocol is required", r.ID)
	}
	if strings.EqualFold(r.Protocol, "unknown") {
		return fmt.Errorf("rule %q: protocol cannot be unknown (unknown is the built-in fallback)", r.ID)
	}
	if r.BaseConfidence <= 0 || r.BaseConfidence > 1 {
		return fmt.Errorf("rule %q: base_confidence must be in (0,1]", r.ID)
	}
	if r.PortBonus < 0 || r.PortBonus > 0.2 {
		return fmt.Errorf("rule %q: port_bonus must be in [0,0.2]", r.ID)
	}
	if r.Match.Type == "" {
		r.Match.Type = "regex"
	}
	if r.Match.Pattern == "" {
		return fmt.Errorf("rule %q: match.pattern is required", r.ID)
	}

	switch r.Match.Type {
	case "regex":
		re, err := regexp.Compile(r.Match.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: invalid regex: %w", r.ID, err)
		}
		r.re = re
	case "bytes_hex":
		raw, err := hex.DecodeString(strings.ReplaceAll(r.Match.Pattern, " ", ""))
		if err != nil {
			return fmt.Errorf("rule %q: invalid hex pattern: %w", r.ID, err)
		}
		r.hexBytes = raw
	case "prefix", "contains":
		// 直接使用字符串比较，无需编译。
	default:
		return fmt.Errorf("rule %q: unknown match type %q", r.ID, r.Match.Type)
	}

	for _, hint := range r.OSHints {
		if hint.Pattern == "" || hint.Value == "" {
			return fmt.Errorf("rule %q: os_hint requires pattern and value", r.ID)
		}
		re, err := regexp.Compile(hint.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: invalid os_hint regex: %w", r.ID, err)
		}
		r.osRes = append(r.osRes, re)
	}
	return nil
}

// Matches 判断规则是否命中。
func (r *Rule) Matches(raw []byte, text string) bool {
	switch r.Match.Type {
	case "bytes_hex":
		return len(raw) >= len(r.hexBytes) && bytes.HasPrefix(raw, r.hexBytes)
	case "prefix":
		return strings.HasPrefix(text, r.Match.Pattern)
	case "contains":
		return strings.Contains(text, r.Match.Pattern)
	default:
		return r.re != nil && r.re.MatchString(text)
	}
}

// Extract 从命中的 banner 中提取 product/version/os_hint。
// 约定：正则命名捕获组 version 提取版本，product 可覆盖规则中的固定产品名。
func (r *Rule) Extract(text string) (product, version, osHint string) {
	product = r.Product
	if r.re != nil {
		m := r.re.FindStringSubmatch(text)
		if m != nil {
			for i, name := range r.re.SubexpNames() {
				switch name {
				case "version":
					version = m[i]
				case "product":
					if product == "" {
						product = m[i]
					}
				}
			}
		}
	}
	for i, re := range r.osRes {
		if re.MatchString(text) {
			osHint = r.OSHints[i].Value
			break
		}
	}
	return product, strings.TrimSpace(version), osHint
}

// PortMatched 判断端口是否命中规则声明的先验端口。
func (r *Rule) PortMatched(port int) bool {
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}
