package integration

import (
	"os"
	"strings"
	"testing"
)

func copyTrust(target string) error {
	data, err := os.ReadFile("../fixture/testdata/trust/trust_ed25519_only.json")
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}

func firstToken(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if line == "" || strings.HasPrefix(line, "total:") {
			continue
		}
		return strings.Fields(line)[0]
	}
	t.Fatal("no entry line found in trust list output")
	return ""
}
