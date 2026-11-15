package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"signer/internal/contract"
	sigcrypto "signer/internal/crypto"
	"signer/internal/fileio"
	"signer/internal/jsonx"
	"signer/internal/keys"
	"signer/internal/manifest"
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
	pub, err := keys.ParsePublic([]byte(e.PublicKeyPEM))
	if err != nil {
		return fmt.Errorf("%w: invalid public key: %v", jsonx.ErrFormat, err)
	}
	algorithm, err := sigcrypto.PublicAlgorithm(pub)
	if err != nil {
		return jsonx.ErrFormat
	}
	id, err := keys.Fingerprint(pub)
	if err != nil || id != e.KeyID || string(algorithm) != e.Algorithm {
		return jsonx.ErrFormat
	}
	if len(e.Packages) == 0 {
		return jsonx.ErrFormat
	}
	seen := map[string]bool{}
	for _, p := range e.Packages {
		if !manifest.ValidPackage(p) || seen[p] {
			return jsonx.ErrFormat
		}
		seen[p] = true
	}
	return nil
}

func Parse(data []byte) (Store, error) {
	v, err := jsonx.Decode(data)
	if err != nil {
		return Store{}, err
	}
	o, err := jsonx.Object(v, storeFields...)
	if err != nil {
		return Store{}, err
	}
	if o["schema"] != Schema {
		return Store{}, jsonx.ErrFormat
	}
	entries, ok := o["keys"].([]any)
	if !ok {
		return Store{}, jsonx.ErrFormat
	}
	s := New()
	seen := map[string]bool{}
	for _, v := range entries {
		o, err := jsonx.Object(v, entryFields...)
		if err != nil {
			return Store{}, err
		}
		p, ok := o["packages"].([]any)
		if !ok {
			return Store{}, jsonx.ErrFormat
		}
		for _, v := range p {
			if _, ok := v.(string); !ok {
				return Store{}, jsonx.ErrFormat
			}
		}
		var e entryJSON
		if err := jsonx.Into(o, &e); err != nil {
			return Store{}, err
		}
		entry := Entry{e.KeyID, e.Algorithm, e.PublicKeyPEM, e.Packages}
		if err := entry.Validate(); err != nil {
			return Store{}, err
		}
		if seen[entry.KeyID] {
			return Store{}, jsonx.ErrFormat
		}
		seen[entry.KeyID] = true
		s.Keys = append(s.Keys, entry)
	}
	return s, nil
}

func Load(path string) (Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Store{}, err
	}
	return Parse(b)
}

func SaveAtomic(path string, store Store) error {
	j := storeJSON{Schema: store.Schema, Keys: []entryJSON{}}
	for _, e := range store.Keys {
		j.Keys = append(j.Keys, entryJSON{e.KeyID, e.Algorithm, e.PublicKeyPEM, e.Packages})
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if _, err := Parse(b); err != nil {
		return err
	}
	return fileio.WriteAtomic(path, append(b, '\n'), 0644, true)
}

func (s *Store) Add(entry Entry) (bool, error) {
	if s == nil || s.Schema != Schema {
		return false, jsonx.ErrFormat
	}
	if err := entry.Validate(); err != nil {
		return false, err
	}
	for i, e := range s.Keys {
		if e.KeyID != entry.KeyID {
			continue
		}
		if err := e.Validate(); err != nil {
			return false, err
		}
		changed := false
		for _, p := range entry.Packages {
			if !slices.Contains(s.Keys[i].Packages, p) {
				s.Keys[i].Packages = append(s.Keys[i].Packages, p)
				changed = true
			}
		}
		return changed, nil
	}
	entry.Packages = slices.Clone(entry.Packages)
	s.Keys = append(s.Keys, entry)
	return true, nil
}

func (s *Store) Remove(keyID string) bool {
	if s == nil {
		return false
	}
	for i, e := range s.Keys {
		if e.KeyID == keyID {
			s.Keys = append(s.Keys[:i], s.Keys[i+1:]...)
			return true
		}
	}
	return false
}

func Find(store Store, keyID string) (Entry, bool) {
	for _, e := range store.Keys {
		if e.KeyID == keyID {
			e.Packages = slices.Clone(e.Packages)
			return e, true
		}
	}
	return Entry{}, false
}

func EntryFromPublicPEM(publicKeyPEM []byte, algorithm string, packages []string) (Entry, error) {
	pub, err := keys.ParsePublic(publicKeyPEM)
	if err != nil {
		return Entry{}, err
	}
	a, err := sigcrypto.PublicAlgorithm(pub)
	if err != nil {
		return Entry{}, err
	}
	if algorithm != "" && algorithm != string(a) {
		return Entry{}, jsonx.ErrFormat
	}
	id, err := keys.Fingerprint(pub)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{id, string(a), string(publicKeyPEM), slices.Clone(packages)}
	return e, e.Validate()
}
