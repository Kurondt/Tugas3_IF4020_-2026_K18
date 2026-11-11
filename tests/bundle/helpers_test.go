package bundle_test

import "path/filepath"

const testdataDir = "../fixture/testdata"

type profileFixture struct {
	name   string
	bundle string
}

var profiles = []profileFixture{
	{"ed25519", "bundle_ed25519.json"},
	{"ecdsa-p256", "bundle_ecdsa_p256_sha256.json"},
	{"rsa-pss", "bundle_rsa_pss_sha256.json"},
}

func fixturePath(elements ...string) string {
	return filepath.Join(testdataDir, filepath.Join(elements...))
}
