package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"signer/internal/sbom"
	"signer/internal/verifier"
)

func runSBOM(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: JARsign sbom <sign|verify> --help")
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: JARsign sbom <sign|verify> --help")
		return 0
	}
	if args[0] != "sign" && args[0] != "verify" {
		fmt.Fprintln(stderr, "unknown SBOM subcommand")
		return 2
	}
	sign := args[0] == "sign"
	fs := newFlagSet("sbom "+args[0], stderr)
	var file, artifact, pkg, version, key, out, bundle, sbomPath, sbomBundle, store string
	var force, asJSON bool
	fs.StringVar(&file, "file", "", "SBOM to sign, or release to verify")
	fs.StringVar(&pkg, "package", "", "expected package")
	fs.StringVar(&version, "version", "", "expected version")
	if sign {
		fs.StringVar(&artifact, "artifact", "", "release referenced by the SBOM")
		fs.StringVar(&key, "key", "", "PKCS8 private key")
		fs.StringVar(&out, "out", "", "SBOM bundle output")
		fs.BoolVar(&force, "force", false, "overwrite existing bundle")
	} else {
		fs.StringVar(&bundle, "bundle", "", "release bundle")
		fs.StringVar(&sbomPath, "sbom", "", "SBOM JSON file")
		fs.StringVar(&sbomBundle, "sbom-bundle", "", "SBOM bundle")
		fs.StringVar(&store, "trust-store", "", "trusted publisher configuration")
		fs.BoolVar(&asJSON, "json", false, "print JSON result")
	}
	emit := func(r sbom.Result) int {
		if asJSON || jsonRequested(args[1:]) {
			json.NewEncoder(stdout).Encode(r)
		} else {
			fmt.Fprintf(stdout, "%s: %s\n", r.Status, r.Message)
		}
		fmt.Fprintf(stderr, "sbom verify: %s\n", r.Status)
		return r.ExitCode()
	}
	if code := handleParse(fs, args[1:], stderr); code >= 0 {
		if code == 2 && !sign {
			return emit(sbom.Result{Status: "INPUT_ERROR", Message: "invalid command parameters"})
		}
		return code
	}
	required := map[string]string{"--file": file, "--package": pkg, "--version": version}
	if sign {
		required["--artifact"] = artifact
		required["--key"] = key
		required["--out"] = out
	} else {
		required["--bundle"] = bundle
		required["--sbom"] = sbomPath
		required["--sbom-bundle"] = sbomBundle
		required["--trust-store"] = store
	}
	if missingParams(fs, stderr, required) {
		if !sign {
			return emit(sbom.Result{Status: "INPUT_ERROR", Message: "missing required parameters"})
		}
		return 2
	}
	if sign {
		r, err := sbom.SignFile(file, artifact, pkg, version, key, out, force)
		if err != nil {
			fmt.Fprintf(stderr, "sbom sign: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "algorithm: %s\nkeyid: %s\nbundle: %s\n", r.Algorithm, r.KeyID, r.BundlePath)
		return 0
	}
	r, err := sbom.Run(sbom.Request{Release: verifier.Request{ArtifactPath: file, BundlePath: bundle, TrustStorePath: store, Package: pkg, Version: version}, SBOMPath: sbomPath, SBOMBundlePath: sbomBundle})
	if err != nil {
		return emit(sbom.Result{Status: "INPUT_ERROR", Message: err.Error()})
	}
	return emit(r)
}
