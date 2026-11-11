package crypto_test

import "path/filepath"

const testdataDir = "../fixture/testdata"

const testMessage = "norsign unit test message"

type profileFixture struct {
	name string
	key  string
}

var profiles = []profileFixture{
	{"ed25519", "ed25519"},
	{"ecdsa-p256", "ecdsa_p256"},
	{"rsa-pss", "rsa_pss_3072"},
}

func fixturePath(elements ...string) string {
	return filepath.Join(testdataDir, filepath.Join(elements...))
}
