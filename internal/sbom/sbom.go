// Package sbom signs inventories as independent artifacts and verifies their
// binding to a separately signed release. It never changes the mandatory formats.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"signer/internal/fileio"
	"signer/internal/jsonx"
	"signer/internal/signing"
	"signer/internal/verifier"
)

const Schema = "jarsign-sbom/v1"
const MaxSize = 16 * 1024 * 1024
const StatusBindingMismatch = "SBOM_BINDING_MISMATCH"

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type Artifact struct {
	SHA256 string `json:"sha256"`
}
type Document struct {
	Schema     string      `json:"schema"`
	Artifact   Artifact    `json:"artifact"`
	Components []Component `json:"components"`
}

func Parse(data []byte) (Document, error) {
	if len(data) > MaxSize {
		return Document{}, jsonx.ErrFormat
	}
	v, err := jsonx.Decode(data)
	if err != nil {
		return Document{}, err
	}
	o, err := jsonx.Object(v, "schema", "artifact", "components")
	if err != nil {
		return Document{}, err
	}
	if _, err := jsonx.Object(o["artifact"], "sha256"); err != nil {
		return Document{}, err
	}
	components, ok := o["components"].([]any)
	if !ok {
		return Document{}, jsonx.ErrFormat
	}
	for _, v := range components {
		c, err := jsonx.Object(v, "name", "version")
		if err != nil {
			return Document{}, err
		}
		for _, field := range []string{"name", "version"} {
			s, ok := c[field].(string)
			if !ok || strings.TrimSpace(s) == "" {
				return Document{}, jsonx.ErrFormat
			}
		}
	}
	var d Document
	if err := jsonx.Into(o, &d); err != nil {
		return Document{}, err
	}
	if d.Schema != Schema || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d.Artifact.SHA256) {
		return Document{}, jsonx.ErrFormat
	}
	return d, nil
}

func SignFile(path, artifactPath, pkg, version, keyPath, out string, force bool) (signing.Result, error) {
	if err := fileio.RejectAliases(out, path, artifactPath, keyPath); err != nil {
		return signing.Result{}, err
	}
	b, err := fileio.ReadLimit(path, MaxSize)
	if err != nil {
		return signing.Result{}, err
	}
	d, err := Parse(b)
	if err != nil {
		return signing.Result{}, err
	}
	f, err := fileio.OpenArtifact(artifactPath)
	if err != nil {
		return signing.Result{}, err
	}
	defer f.Close()
	_, hash, err := fileio.Hash(f)
	if err != nil {
		return signing.Result{}, err
	}
	if hash != d.Artifact.SHA256 {
		return signing.Result{}, fmt.Errorf("SBOM release SHA-256 differs")
	}
	return signing.SignBytes(b, filepath.Base(path), pkg, version, keyPath, out, force)
}

type Request struct {
	Release        verifier.Request
	SBOMPath       string
	SBOMBundlePath string
}
type Result struct {
	Valid   bool             `json:"valid"`
	Status  string           `json:"status"`
	Message string           `json:"message"`
	Release *verifier.Result `json:"release"`
	SBOM    *verifier.Result `json:"sbom"`
}

func (r Result) ExitCode() int {
	if r.Valid && r.Status == "OK" {
		return 0
	}
	if r.Status == "INPUT_ERROR" {
		return 2
	}
	return 1
}

func Run(req Request) (Result, error) {
	r := Result{}
	fail := func(status string, message any) (Result, error) {
		r.Status = status
		r.Message = fmt.Sprint(message)
		return r, nil
	}
	release, err := verifier.Run(req.Release)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	r.Release = &release
	if !release.Valid {
		return fail(release.Status, release.Message)
	}
	sreq := req.Release
	sreq.ArtifactPath = req.SBOMPath
	sreq.BundlePath = req.SBOMBundlePath
	sresult, err := verifier.Run(sreq)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	r.SBOM = &sresult
	if !sresult.Valid {
		return fail(sresult.Status, sresult.Message)
	}
	b, err := fileio.ReadLimit(req.SBOMPath, MaxSize)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	d, err := Parse(b)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != sresult.ArtifactSHA256() {
		return fail("ARTIFACT_MISMATCH", "SBOM changed after verification")
	}
	if d.Artifact.SHA256 != release.ArtifactSHA256() {
		return fail(StatusBindingMismatch, "SBOM does not reference the release SHA-256")
	}
	r.Valid = true
	r.Status = "OK"
	r.Message = "release, SBOM, and release binding are valid"
	return r, nil
}
