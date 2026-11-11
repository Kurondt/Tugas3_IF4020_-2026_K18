package trust

import (
	"signer/internal/contract"
)

const Schema = "minisign-trust/v1"

var (
	storeFields = []string{"schema", "keys"}
	entryFields = []string{"keyid", "algorithm", "public_key_pem", "packages"}

	ErrNotImplemented = contract.ErrNotImplemented
)

type Entry struct {
	KeyID        string
	Algorithm    string
	PublicKeyPEM string
	Packages     []string
}

type Store struct {
	Schema string
	Keys   []Entry
}

type entryJSON struct {
	KeyID        string   `json:"keyid"`
	Algorithm    string   `json:"algorithm"`
	PublicKeyPEM string   `json:"public_key_pem"`
	Packages     []string `json:"packages"`
}

type storeJSON struct {
	Schema string      `json:"schema"`
	Keys   []entryJSON `json:"keys"`
}

func New() Store {
	return Store{Schema: Schema, Keys: []Entry{}}
}

func (e Entry) Validate() error {
	return ErrNotImplemented
}

func Parse(data []byte) (Store, error) {
	return Store{}, ErrNotImplemented
}

func Load(path string) (Store, error) {
	return Store{}, ErrNotImplemented
}

func SaveAtomic(path string, store Store) error {
	return ErrNotImplemented
}

func (s *Store) Add(entry Entry) (bool, error) {
	return false, ErrNotImplemented
}

func (s *Store) Remove(keyID string) bool {
	return false
}

func Find(store Store, keyID string) (Entry, bool) {
	return Entry{}, false
}

func EntryFromPublicPEM(publicKeyPEM []byte, algorithm string, packages []string) (Entry, error) {
	return Entry{}, ErrNotImplemented
}
