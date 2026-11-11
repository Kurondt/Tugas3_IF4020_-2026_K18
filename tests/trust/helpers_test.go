package trust_test

import "path/filepath"

const testdataDir = "../fixture/testdata"

const (
	mainPackage  = "contoh-app"
	otherPackage = "other-app"
	unknownKeyID = "0000000000000000000000000000000000000000000000000000000000000000"
)

func fixturePath(elements ...string) string {
	return filepath.Join(testdataDir, filepath.Join(elements...))
}
