package api

import (
	"testing"
)

func TestParseInputsForms(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		want  int
		isErr bool
	}{
		{"array", `[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-x"}]`, 1, false},
		{"wrapper-records", `{"records":[{"ip":"1.1.1.1","port":22,"banner":"x"}]}`, 1, false},
		{"wrapper-items", `{"items":[{"ip":"a"},{"ip":"b"}]}`, 2, false},
		{"single", `{"ip":"1.1.1.1","port":"22","banner":"x"}`, 1, false},
		{"double-encoded", `"[{\"ip\":\"1.1.1.1\",\"port\":22,\"banner\":\"x\"}]"`, 1, false},
		{"empty-array", `[]`, 0, false},
		{"invalid", `not json`, 0, true},
		{"unsupported-object", `{"foo":1}`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseInputs([]byte(tc.body))
			if tc.isErr {
				if err == nil {
					t.Fatalf("expected error, got %d records", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("records = %d, want %d", len(got), tc.want)
			}
		})
	}
}

func TestParseInputsRepairsInvalidHexEscape(t *testing.T) {
	// 部分扫描器会输出非法的 \x00（JSON 不允许），应被修复而不是整批 400。
	body := `[{"ip":"1.1.1.1","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	got, err := ParseInputs([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1", len(got))
	}
	if got[0].Banner != "J\x00\x00\x00\n8.0.32\x00" {
		t.Fatalf("banner not repaired: %q", got[0].Banner)
	}
}

func TestParseInputsKeepsEscapedBackslash(t *testing.T) {
	body := `[{"ip":"1.1.1.1","port":3306,"banner":"J\\x00\\x00\\x00\\n8.0.32\\x00"}]`
	got, err := ParseInputs([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Banner != `J\x00\x00\x00\n8.0.32\x00` {
		t.Fatalf("banner altered: %q", got[0].Banner)
	}
}
