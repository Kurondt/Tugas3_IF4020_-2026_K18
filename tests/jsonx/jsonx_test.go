package jsonx_test

import (
	"strings"
	"testing"

	"signer/internal/jsonx"
)

func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`{"x":1,"\u0078":2}`, `{"x":[{"a":1,"a":2}]}`, `{} {}`, "\xef\xbb\xbf{}", "{\"x\":\"\xff\"}", `{"x":1,}`, `[1,]`, strings.Repeat("[", 130) + strings.Repeat("]", 130)} {
		t.Run(s[:min(len(s), 40)], func(t *testing.T) {
			if _, err := jsonx.Decode([]byte(s)); err == nil {
				t.Fatalf("accepted %q", s)
			}
		})
	}
	if _, err := jsonx.Decode([]byte(`{"a":[true,false,null,0,"ok",{}]}`)); err != nil {
		t.Fatal(err)
	}
}
