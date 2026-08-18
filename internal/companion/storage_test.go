package companion

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeConfigStore struct {
	name      string
	config    *Config
	loadErr   error
	saveErr   error
	deleteErr error
	saveAs    *Config
	events    *[]string
	saves     []Config
	deletes   int
}

func (store *fakeConfigStore) record(operation string) {
	if store.events != nil {
		*store.events = append(*store.events, store.name+"."+operation)
	}
}

func (store *fakeConfigStore) Load() (Config, error) {
	store.record("load")
	if store.loadErr != nil {
		return Config{}, store.loadErr
	}
	if store.config == nil {
		return Config{}, os.ErrNotExist
	}
	return *store.config, nil
}

func (store *fakeConfigStore) Save(config Config) error {
	store.record("save")
	store.saves = append(store.saves, config)
	if store.saveErr != nil {
		return store.saveErr
	}
	if store.saveAs != nil {
		config = *store.saveAs
	}
	store.config = &config
	return nil
}

func (store *fakeConfigStore) Delete() error {
	store.record("delete")
	store.deletes++
	if store.deleteErr != nil {
		return store.deleteErr
	}
	store.config = nil
	return nil
}

func TestFileConfigStoreRoundTripUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "companion.json")
	store := FileConfigStore{Path: path}
	config := validTestConfig(t)
	if err := store.Save(config); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permission := info.Mode().Perm(); permission != 0o600 {
		t.Fatalf("configuration permission = %o, want 600", permission)
	}
	loaded, err := store.Load()
	if err != nil || loaded != config {
		t.Fatalf("loaded configuration = %#v, error = %v", loaded, err)
	}
	if err := store.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(); err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}
}

func TestFileConfigStoreRejectsUnsafeFiles(t *testing.T) {
	config := validTestConfig(t)

	t.Run("weak permissions", func(t *testing.T) {
		store := FileConfigStore{Path: filepath.Join(t.TempDir(), "companion.json")}
		if err := store.Save(config); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(store.Path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("loaded a configuration readable by other users")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := FileConfigStore{Path: filepath.Join(directory, "target.json")}
		if err := target.Save(config); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "companion.json")
		if err := os.Symlink(target.Path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := (FileConfigStore{Path: link}).Load(); err == nil {
			t.Fatal("loaded a configuration through a symlink")
		}
	})

	t.Run("non-regular", func(t *testing.T) {
		if _, err := (FileConfigStore{Path: t.TempDir()}).Load(); err == nil {
			t.Fatal("loaded a configuration from a non-regular file")
		}
	})
}

func TestConfigStoresRejectOversizedConfiguration(t *testing.T) {
	config := validTestConfig(t)
	config.ControllerLabel = strings.Repeat("x", maxStoredConfigBytes)
	if err := (FileConfigStore{Path: filepath.Join(t.TempDir(), "companion.json")}).Save(config); err == nil {
		t.Fatal("file store accepted an unreadable oversized configuration")
	}
	if _, err := encodeStoredConfig(config); err == nil {
		t.Fatal("Keychain encoding accepted an unreadable oversized configuration")
	}
}

func TestMigrateConfigStoreIsVerifiedAndIdempotent(t *testing.T) {
	config := validTestConfig(t)
	t.Run("clean install is a no-op", func(t *testing.T) {
		legacy, keychain := &fakeConfigStore{}, &fakeConfigStore{}
		if err := MigrateConfigStore(legacy, keychain); err != nil {
			t.Fatal(err)
		}
		if legacy.deletes != 0 || len(keychain.saves) != 0 {
			t.Fatal("empty stores were changed")
		}
	})

	t.Run("migrate and verify before delete", func(t *testing.T) {
		var events []string
		legacy := &fakeConfigStore{name: "legacy", config: &config, events: &events}
		keychain := &fakeConfigStore{name: "keychain", events: &events}
		if err := MigrateConfigStore(legacy, keychain); err != nil {
			t.Fatal(err)
		}
		want := []string{"keychain.load", "legacy.load", "keychain.save", "keychain.load", "legacy.delete"}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("migration order = %v, want %v", events, want)
		}
		if legacy.config != nil || keychain.config == nil || *keychain.config != config {
			t.Fatal("migration did not move the complete configuration")
		}
	})

	t.Run("valid Keychain without legacy wins", func(t *testing.T) {
		secureConfig := config
		legacy := &fakeConfigStore{}
		keychain := &fakeConfigStore{config: &secureConfig}
		if err := MigrateConfigStore(legacy, keychain); err != nil {
			t.Fatal(err)
		}
		if legacy.deletes != 0 || len(keychain.saves) != 0 {
			t.Fatal("Keychain-only configuration was changed")
		}
	})

	t.Run("finish interrupted equal migration", func(t *testing.T) {
		legacyConfig, secureConfig := config, config
		legacy := &fakeConfigStore{config: &legacyConfig}
		keychain := &fakeConfigStore{config: &secureConfig}
		if err := MigrateConfigStore(legacy, keychain); err != nil {
			t.Fatal(err)
		}
		if legacy.config != nil || len(keychain.saves) != 0 || legacy.deletes != 1 {
			t.Fatal("equal migration was not completed idempotently")
		}
	})

	t.Run("conflict leaves both untouched", func(t *testing.T) {
		legacyConfig, secureConfig := config, config
		secureConfig.ControllerLabel = "Different controller"
		legacy := &fakeConfigStore{config: &legacyConfig}
		keychain := &fakeConfigStore{config: &secureConfig}
		err := MigrateConfigStore(legacy, keychain)
		if !errors.Is(err, ErrConfigStoreMismatch) {
			t.Fatalf("conflict error = %v", err)
		}
		if legacy.config == nil || keychain.config == nil || legacy.deletes != 0 || len(keychain.saves) != 0 {
			t.Fatal("conflicting migration changed a store")
		}
	})

	t.Run("verification failure retains legacy", func(t *testing.T) {
		verified := config
		verified.ControllerLabel = "Wrong readback"
		legacy := &fakeConfigStore{config: &config}
		keychain := &fakeConfigStore{saveAs: &verified}
		err := MigrateConfigStore(legacy, keychain)
		if !errors.Is(err, ErrConfigStoreMismatch) {
			t.Fatalf("verification error = %v", err)
		}
		if legacy.config == nil || legacy.deletes != 0 {
			t.Fatal("verification failure removed the legacy configuration")
		}
	})

	t.Run("store failure retains legacy", func(t *testing.T) {
		failure := errors.New("Keychain unavailable")
		legacy := &fakeConfigStore{config: &config}
		keychain := &fakeConfigStore{saveErr: failure}
		if err := MigrateConfigStore(legacy, keychain); !errors.Is(err, failure) {
			t.Fatalf("save error = %v", err)
		}
		if legacy.config == nil || legacy.deletes != 0 {
			t.Fatal("store failure removed the legacy configuration")
		}
	})
}

func TestNewAppWithStoreLoadsValidatedConfiguration(t *testing.T) {
	config := validTestConfig(t)
	config.LinkRevoked = true
	store := &fakeConfigStore{config: &config}
	app, err := NewAppWithStore(t.Context(), store, DefaultRelayURL)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if state := app.state(); !state.Configured || state.LinkID != config.LinkID || state.Status == "Not enrolled" {
		t.Fatalf("stored state = %#v", state)
	}

	invalid := config
	invalid.Secret = "invalid"
	if _, err := NewAppWithStore(t.Context(), &fakeConfigStore{config: &invalid}, DefaultRelayURL); err == nil {
		t.Fatal("accepted an invalid configuration from a store")
	}
}
