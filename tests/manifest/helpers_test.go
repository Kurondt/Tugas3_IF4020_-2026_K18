package manifest_test

import "path/filepath"

const testdataDir = "../fixture/testdata"

const (
	mainPackage = "contoh-app"
	testVersion = "1.0.0"
	testKeyID   = "0000000000000000000000000000000000000000000000000000000000000000"
)

func fixturePath(elements ...string) string {
	return filepath.Join(testdataDir, filepath.Join(elements...))
}
