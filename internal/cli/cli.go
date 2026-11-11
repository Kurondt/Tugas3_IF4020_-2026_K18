package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	sigcrypto "signer/internal/crypto"
	"signer/internal/keys"
	"signer/internal/manifest"
	"signer/internal/signing"
	"signer/internal/trust"
	"signer/internal/verifier"
)

const version = "1.0.0"

var programVersion = version

const usageText = `
Usage:
  norsign <command> [parameters]

Commands:
  keygen       Generate a key pair
  sign         Sign an artifact and write a bundle
  verify       Verify a bundle against an artifact and trust store
  trust add    Add a public key to the trust store
  trust list   List trusted keys
  trust remove Remove a trusted key by keyid

Global options:
  --help       Show this help
  --version    Show program version

Run "norsign <command> --help" for command parameters.`

type keygenParams struct {
	algorithm string
	out       string
	force     bool
}

type signParams struct {
	file    string
	pkg     string
	version string
	key     string
	out     string
	force   bool
}

type verifyParams struct {
	file       string
	bundlePath string
	trustStore string
	pkg        string
	version    string
	json       bool
}

type trustAddParams struct {
	key   string
	pkg   string
	store string
}

type trustListParams struct {
	store string
}

type trustRemoveParams struct {
	keyID string
	store string
}

func Main(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "--help", "-h", "help":
		fmt.Fprintln(stdout, usageText)
		return 0
	case "--version":
		fmt.Fprintf(stdout, "norsign version %s\n", programVersion)
		return 0
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "trust":
		return runTrust(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s\n", args[0], usageText)
		return 2
	}
}

func runKeygen(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("keygen", stderr)
	params := keygenParams{}
	fs.StringVar(&params.algorithm, "algorithm", "", "algorithm profile (rsa-pss-sha256, ecdsa-p256-sha256, ed25519)")
	fs.StringVar(&params.out, "out", "", "output file name prefix")
	fs.BoolVar(&params.force, "force", false, "overwrite existing key files")
	if handleParse(fs, args, stderr) {
		return 2
	}
	if missingParams(fs, stderr, map[string]string{
		"--algorithm": params.algorithm,
		"--out":       params.out,
	}) {
		return 2
	}
	if err := manifest.ValidateAlgorithm(params.algorithm); err != nil {
		fmt.Fprintf(stderr, "keygen: %v\n", err)
		return 2
	}
	keyID, err := keys.GenerateAndSave(sigcrypto.Algorithm(params.algorithm), params.out, params.force)
	if err != nil {
		fmt.Fprintf(stderr, "keygen: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "algorithm: %s\nkeyid: %s\nprivate key: %s.key.pem\npublic key: %s.pub.pem\n", params.algorithm, keyID, params.out, params.out)
	return 0
}

func runSign(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("sign", stderr)
	params := signParams{}
	fs.StringVar(&params.file, "file", "", "artifact file to sign")
	fs.StringVar(&params.pkg, "package", "", "package name")
	fs.StringVar(&params.version, "version", "", "release version")
	fs.StringVar(&params.key, "key", "", "private key file (PKCS8 PEM)")
	fs.StringVar(&params.out, "out", "", "output bundle file")
	fs.BoolVar(&params.force, "force", false, "overwrite existing bundle file")
	if handleParse(fs, args, stderr) {
		return 2
	}
	if missingParams(fs, stderr, map[string]string{
		"--file":    params.file,
		"--package": params.pkg,
		"--version": params.version,
		"--key":     params.key,
		"--out":     params.out,
	}) {
		return 2
	}
	result, err := signing.SignFile(params.file, params.pkg, params.version, params.key, params.out, params.force)
	if err != nil {
		fmt.Fprintf(stderr, "sign: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "algorithm: %s\nkeyid: %s\nbundle: %s\n", result.Algorithm, result.KeyID, result.BundlePath)
	return 0
}

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	params := verifyParams{}
	fs.StringVar(&params.file, "file", "", "artifact file to verify")
	fs.StringVar(&params.bundlePath, "bundle", "", "bundle file")
	fs.StringVar(&params.trustStore, "trust-store", "", "trust store file")
	fs.StringVar(&params.pkg, "package", "", "expected package name")
	fs.StringVar(&params.version, "version", "", "expected release version")
	fs.BoolVar(&params.json, "json", false, "print the verification result as JSON")
	if handleParse(fs, args, stderr) {
		return 2
	}
	if missingParams(fs, stderr, map[string]string{
		"--file":        params.file,
		"--bundle":      params.bundlePath,
		"--trust-store": params.trustStore,
		"--package":     params.pkg,
		"--version":     params.version,
	}) {
		if params.json {
			writeResult(stdout, verifier.Result{
				Status:  string(verifier.StatusInputError),
				Message: "missing required parameters",
			})
		}
		return 2
	}
	result, err := verifier.Run(verifier.Request{
		ArtifactPath:   params.file,
		BundlePath:     params.bundlePath,
		TrustStorePath: params.trustStore,
		Package:        params.pkg,
		Version:        params.version,
	})
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 2
	}
	if params.json {
		writeResult(stdout, result)
	} else {
		fmt.Fprintf(stdout, "%s: %s\n", result.Status, result.Message)
	}
	fmt.Fprintf(stderr, "verify: %s\n", result.Status)
	return result.ExitCode()
}

func runTrust(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "trust: missing subcommand (add, list, remove)")
		return 2
	}
	switch args[0] {
	case "add":
		return runTrustAdd(args[1:], stdout, stderr)
	case "list":
		return runTrustList(args[1:], stdout, stderr)
	case "remove":
		return runTrustRemove(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "trust: unknown subcommand %q (expected add, list, remove)\n", args[0])
		return 2
	}
}

func runTrustAdd(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("trust add", stderr)
	params := trustAddParams{}
	fs.StringVar(&params.key, "key", "", "public key file (SPKI PEM)")
	fs.StringVar(&params.pkg, "package", "", "package name to allow")
	fs.StringVar(&params.store, "store", "", "trust store file")
	if handleParse(fs, args, stderr) {
		return 2
	}
	if missingParams(fs, stderr, map[string]string{
		"--key":     params.key,
		"--package": params.pkg,
		"--store":   params.store,
	}) {
		return 2
	}
	if !manifest.ValidPackage(params.pkg) {
		fmt.Fprintf(stderr, "trust add: package %q does not match the required pattern\n", params.pkg)
		return 2
	}
	publicKeyPEM, err := os.ReadFile(params.key)
	if err != nil {
		fmt.Fprintf(stderr, "trust add: %v\n", err)
		return 2
	}
	entry, err := trust.EntryFromPublicPEM(publicKeyPEM, "", []string{params.pkg})
	if err != nil {
		fmt.Fprintf(stderr, "trust add: %v\n", err)
		return 2
	}
	store, err := loadOrCreateStore(params.store)
	if err != nil {
		fmt.Fprintf(stderr, "trust add: %v\n", err)
		return 2
	}
	changed, err := store.Add(entry)
	if err != nil {
		fmt.Fprintf(stderr, "trust add: %v\n", err)
		return 2
	}
	if changed {
		if err := trust.SaveAtomic(params.store, store); err != nil {
			fmt.Fprintf(stderr, "trust add: %v\n", err)
			return 2
		}
	}
	mergedEntry, _ := trust.Find(store, entry.KeyID)
	fmt.Fprintf(stdout, "keyid: %s\nalgorithm: %s\npackages: %s\nstatus: %s\n", entry.KeyID, entry.Algorithm, strings.Join(mergedEntry.Packages, ", "), addedStatus(changed))
	return 0
}

func runTrustList(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("trust list", stderr)
	params := trustListParams{}
	fs.StringVar(&params.store, "store", "", "trust store file")
	if handleParse(fs, args, stderr) {
		return 2
	}
	if missingParams(fs, stderr, map[string]string{"--store": params.store}) {
		return 2
	}
	store, err := trust.Load(params.store)
	if err != nil {
		fmt.Fprintf(stderr, "trust list: %v\n", err)
		return 2
	}
	for _, entry := range store.Keys {
		fmt.Fprintf(stdout, "%s %s %s\n", entry.KeyID, entry.Algorithm, strings.Join(entry.Packages, ","))
	}
	fmt.Fprintf(stdout, "total: %d\n", len(store.Keys))
	return 0
}

func runTrustRemove(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := newFlagSet("trust remove", stderr)
	params := trustRemoveParams{}
	fs.StringVar(&params.keyID, "keyid", "", "keyid fingerprint to remove")
	fs.StringVar(&params.store, "store", "", "trust store file")
	if handleParse(fs, args, stderr) {
		return 2
	}
	if missingParams(fs, stderr, map[string]string{
		"--keyid": params.keyID,
		"--store": params.store,
	}) {
		return 2
	}
	store, err := trust.Load(params.store)
	if err != nil {
		fmt.Fprintf(stderr, "trust remove: %v\n", err)
		return 2
	}
	if !store.Remove(params.keyID) {
		fmt.Fprintf(stderr, "trust remove: keyid %q not found\n", params.keyID)
		return 2
	}
	if err := trust.SaveAtomic(params.store, store); err != nil {
		fmt.Fprintf(stderr, "trust remove: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "removed: %s\n", params.keyID)
	return 0
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func handleParse(fs *flag.FlagSet, args []string, stderr io.Writer) bool {
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n\nRun \"norsign %s --help\" for usage.\n", fs.Name(), err, fs.Name())
		return true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return true
	}
	return false
}

func missingParams(fs *flag.FlagSet, stderr io.Writer, values map[string]string) bool {
	missing := false
	for name, value := range values {
		if value == "" {
			fmt.Fprintf(stderr, "%s: missing required parameter %s\n", fs.Name(), name)
			missing = true
		}
	}
	return missing
}

func loadOrCreateStore(path string) (trust.Store, error) {
	store, err := trust.Load(path)
	if err == nil {
		return store, nil
	}
	if !os.IsNotExist(err) {
		return trust.Store{}, err
	}
	return trust.New(), nil
}

func addedStatus(changed bool) string {
	if changed {
		return "added"
	}
	return "unchanged"
}

func writeResult(stdout io.Writer, result verifier.Result) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return
	}
	fmt.Fprintf(stdout, "%s\n", encoded)
}
