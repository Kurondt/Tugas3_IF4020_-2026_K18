// norsign-bench records reproducible assignment metrics outside the production CLI.
package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"signer/internal/bundle"
	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
	"signer/internal/manifest"
	"signer/internal/trust"
)

type sample struct {
	Algorithm   string
	Bytes       int
	Metric      string
	Iteration   int
	Nanoseconds int64
}
type summary struct {
	Algorithm string  `json:"algorithm"`
	Bytes     int     `json:"artifact_bytes"`
	Metric    string  `json:"metric"`
	Samples   int     `json:"samples"`
	Median    float64 `json:"median_ns"`
	P95       int64   `json:"p95_ns"`
}
type sizes struct {
	Algorithm string `json:"algorithm"`
	Artifact  int    `json:"artifact_bytes"`
	Private   int    `json:"private_der_bytes"`
	Public    int    `json:"public_der_bytes"`
	Signature int    `json:"signature_bytes"`
	Bundle    int    `json:"bundle_bytes"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", "tests/results/benchmark", "result directory")
	binary := flag.String("binary", "bin/norsign", "compiled production executable")
	flag.Parse()
	absolute, err := filepath.Abs(*binary)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absolute); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0755); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "norsign-benchmark-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	var samples []sample
	var statistics []summary
	var lengths []sizes
	measure := func(algorithm string, size int, metric string, warmup, n int, fn func() error) error {
		for i := 0; i < warmup; i++ {
			if err := fn(); err != nil {
				return err
			}
		}
		values := make([]int64, 0, n)
		for i := 0; i < n; i++ {
			start := time.Now()
			if err := fn(); err != nil {
				return err
			}
			elapsed := time.Since(start).Nanoseconds()
			values = append(values, elapsed)
			samples = append(samples, sample{algorithm, size, metric, i + 1, elapsed})
		}
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		median := float64(values[n/2])
		if n%2 == 0 {
			median = (float64(values[n/2-1]) + median) / 2
		}
		statistics = append(statistics, summary{algorithm, size, metric, n, median, values[int(math.Ceil(0.95*float64(n)))-1]})
		return nil
	}
	for _, algorithm := range sigcrypto.ProfileNames() {
		var private crypto.PrivateKey
		err := measure(string(algorithm), 0, "keygen", 0, 5, func() error { var err error; private, err = sigcrypto.Generate(algorithm); return err })
		if err != nil {
			return err
		}
		public, err := keys.PublicFromPrivate(private)
		if err != nil {
			return err
		}
		id, err := keys.Fingerprint(public)
		if err != nil {
			return err
		}
		prefix := filepath.Join(work, string(algorithm))
		if err := keys.SavePrivate(prefix+".key.pem", private); err != nil {
			return err
		}
		if err := keys.SavePublic(prefix+".pub.pem", private); err != nil {
			return err
		}
		pemBytes, err := os.ReadFile(prefix + ".pub.pem")
		if err != nil {
			return err
		}
		entry, err := trust.EntryFromPublicPEM(pemBytes, "", []string{"bench-app"})
		if err != nil {
			return err
		}
		store := trust.New()
		if _, err := store.Add(entry); err != nil {
			return err
		}
		storePath := prefix + "-trust.json"
		if err := trust.SaveAtomic(storePath, store); err != nil {
			return err
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return err
		}
		publicDER, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return err
		}
		signer, err := sigcrypto.NewSigner(private)
		if err != nil {
			return err
		}
		verifier, err := sigcrypto.NewVerifier(public)
		if err != nil {
			return err
		}
		for _, size := range []int{1024, 1048576, 16777216} {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 251)
			}
			artifact := filepath.Join(work, fmt.Sprintf("artifact-%d.bin", size))
			if err := os.WriteFile(artifact, data, 0600); err != nil {
				return err
			}
			hash := sha256.Sum256(data)
			m, err := manifest.Build("bench-app", "1.0.0", algorithm, id, filepath.Base(artifact), int64(size), hex.EncodeToString(hash[:]))
			if err != nil {
				return err
			}
			mb, err := manifest.Canonical(m)
			if err != nil {
				return err
			}
			sig, err := signer.Sign(mb)
			if err != nil {
				return err
			}
			encoded, err := bundle.Build(mb, sig)
			if err != nil {
				return err
			}
			lengths = append(lengths, sizes{string(algorithm), size, len(privateDER), len(publicDER), len(sig), len(encoded)})
			if err := measure(string(algorithm), size, "artifact_sha256", 5, 30, func() error {
				h := sha256.New()
				_, err := io.Copy(h, bytes.NewReader(data))
				_ = h.Sum(nil)
				return err
			}); err != nil {
				return err
			}
			if err := measure(string(algorithm), size, "manifest_sign", 5, 30, func() error { _, err := signer.Sign(mb); return err }); err != nil {
				return err
			}
			if err := measure(string(algorithm), size, "manifest_verify", 5, 30, func() error { return verifier.Verify(mb, sig) }); err != nil {
				return err
			}
			bundlePath := prefix + "-bundle.json"
			signArgs := []string{"sign", "--file", artifact, "--key", prefix + ".key.pem", "--out", bundlePath, "--package", "bench-app", "--version", "1.0.0", "--force"}
			verifyArgs := []string{"verify", "--file", artifact, "--bundle", bundlePath, "--trust-store", storePath, "--package", "bench-app", "--version", "1.0.0", "--json"}
			if err := measure(string(algorithm), size, "cli_sign", 5, 30, func() error { return exec.Command(absolute, signArgs...).Run() }); err != nil {
				return err
			}
			if err := measure(string(algorithm), size, "cli_verify", 5, 30, func() error { return exec.Command(absolute, verifyArgs...).Run() }); err != nil {
				return err
			}
		}
	}
	file, err := os.Create(filepath.Join(*out, "raw.csv"))
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"algorithm", "artifact_bytes", "metric", "iteration", "nanoseconds"}); err != nil {
		file.Close()
		return err
	}
	for _, s := range samples {
		if err := writer.Write([]string{s.Algorithm, fmt.Sprint(s.Bytes), s.Metric, fmt.Sprint(s.Iteration), fmt.Sprint(s.Nanoseconds)}); err != nil {
			file.Close()
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	save := func(name string, value any) error {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(*out, name), append(data, '\n'), 0644)
	}
	if err := save("summary.json", statistics); err != nil {
		return err
	}
	if err := save("sizes.json", lengths); err != nil {
		return err
	}
	info := map[string]any{"recorded_at_utc": time.Now().UTC().Format(time.RFC3339), "go": runtime.Version(), "os": runtime.GOOS, "architecture": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "warmup": 5, "iterations": 30, "keygen_iterations": 5, "clock": "Go time.Since monotonic clock", "median": "middle sorted value; average of two central values for even n", "p95": "nearest-rank ceil(0.95*n), one-based", "artifact_pattern": "byte(i % 251)", "artifact_hash": "in-memory SHA-256, excludes file IO", "manifest_operations": "include algorithm digest, exclude file IO and artifact hash", "cli_operations": "include process startup, IO, parsing, artifact hash, crypto and output; sign uses --force"}
	for name, path := range map[string]string{"cpuinfo": "/proc/cpuinfo", "meminfo": "/proc/meminfo", "os_release": "/etc/os-release"} {
		if b, err := os.ReadFile(path); err == nil {
			value := string(b)
			if name == "cpuinfo" {
				value = strings.SplitN(value, "\n\n", 2)[0]
			}
			if name == "meminfo" {
				value = strings.SplitN(value, "\n", 2)[0]
			}
			info[name] = value
		}
	}
	if executable, err := os.ReadFile(absolute); err == nil {
		digest := sha256.Sum256(executable)
		info["executable_sha256"] = hex.EncodeToString(digest[:])
	}
	if revision, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
		info["base_revision"] = strings.TrimSpace(string(revision))
		info["source_state"] = "local workspace; inspect git diff for uncommitted implementation"
	}
	if kernel, err := exec.Command("uname", "-sr").Output(); err == nil {
		info["kernel"] = strings.TrimSpace(string(kernel))
	}
	if err := save("environment.json", info); err != nil {
		return err
	}
	fmt.Printf("Wrote %d measured samples to %s\n", len(samples), *out)
	return nil
}
