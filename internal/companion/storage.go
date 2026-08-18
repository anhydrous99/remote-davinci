package companion

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultKeychainService = "dev.remote-davinci.companion"
	DefaultKeychainAccount = "configuration-v1"
	maxStoredConfigBytes   = 64 * 1024
)

var (
	ErrConfigStoreMismatch = errors.New("stored companion configurations do not match")
	ErrKeychainUnavailable = errors.New("macOS Keychain requires darwin with cgo enabled")
)

// ConfigStore owns the companion's complete credential record. Load must
// return an error matching os.ErrNotExist when no record exists; Delete is
// idempotent.
type ConfigStore interface {
	Load() (Config, error)
	Save(Config) error
	Delete() error
}

type FileConfigStore struct {
	Path string
}

type KeychainConfigStore struct {
	Service string
	Account string
}

func NewKeychainConfigStore() KeychainConfigStore {
	return KeychainConfigStore{
		Service: DefaultKeychainService,
		Account: DefaultKeychainAccount,
	}
}

func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "companion.json"
	}
	return filepath.Join(home, "Library", "Application Support", "RemoteDavinci", "companion.json")
}

func LoadConfig(path string) (Config, error) {
	return (FileConfigStore{Path: path}).Load()
}

func SaveConfig(path string, config Config) error {
	return (FileConfigStore{Path: path}).Save(config)
}

func (store FileConfigStore) Load() (Config, error) {
	pathInfo, err := os.Lstat(store.Path)
	if err != nil {
		return Config{}, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 {
		return Config{}, errors.New("refusing insecure companion configuration file")
	}
	file, err := os.Open(store.Path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return Config{}, err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || !os.SameFile(pathInfo, openedInfo) {
		return Config{}, errors.New("refusing insecure companion configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStoredConfigBytes+1))
	if err != nil {
		return Config{}, err
	}
	return decodeStoredConfig(data)
}

func (store FileConfigStore) Save(config Config) error {
	if err := config.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(store.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxStoredConfigBytes {
		return errors.New("invalid companion configuration")
	}
	temporary, err := os.CreateTemp(filepath.Dir(store.Path), ".companion-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, store.Path)
}

func (store FileConfigStore) Delete() error {
	err := os.Remove(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func decodeStoredConfig(data []byte) (Config, error) {
	if len(data) == 0 || len(data) > maxStoredConfigBytes {
		return Config{}, errors.New("invalid companion configuration")
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, errors.New("invalid companion configuration")
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func encodeStoredConfig(config Config) ([]byte, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	if len(data) > maxStoredConfigBytes {
		return nil, errors.New("invalid companion configuration")
	}
	return data, nil
}

func (store KeychainConfigStore) identifiers() (string, string, error) {
	service, account := store.Service, store.Account
	if service == "" {
		service = DefaultKeychainService
	}
	if account == "" {
		account = DefaultKeychainAccount
	}
	if strings.ContainsRune(service, 0) || strings.ContainsRune(account, 0) {
		return "", "", errors.New("invalid Keychain item identifier")
	}
	return service, account, nil
}

// MigrateConfigStore is safe to call on every packaged-app launch. A valid
// Keychain record wins, but an equal legacy record is removed to finish a
// previously interrupted migration. Any conflict leaves both records intact.
func MigrateConfigStore(legacy, keychain ConfigStore) error {
	if legacy == nil || keychain == nil {
		return errors.New("configuration stores are required")
	}
	secure, secureErr := keychain.Load()
	if secureErr == nil {
		if err := secure.validate(); err != nil {
			return fmt.Errorf("validate Keychain configuration: %w", err)
		}
		old, oldErr := legacy.Load()
		if errors.Is(oldErr, os.ErrNotExist) {
			return nil
		}
		if oldErr != nil {
			return fmt.Errorf("load legacy configuration: %w", oldErr)
		}
		if err := old.validate(); err != nil {
			return fmt.Errorf("validate legacy configuration: %w", err)
		}
		if old != secure {
			return ErrConfigStoreMismatch
		}
		if err := legacy.Delete(); err != nil {
			return fmt.Errorf("remove migrated legacy configuration: %w", err)
		}
		return nil
	}
	if !errors.Is(secureErr, os.ErrNotExist) {
		return fmt.Errorf("load Keychain configuration: %w", secureErr)
	}

	old, err := legacy.Load()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load legacy configuration: %w", err)
	}
	if err := old.validate(); err != nil {
		return fmt.Errorf("validate legacy configuration: %w", err)
	}
	if err := keychain.Save(old); err != nil {
		return fmt.Errorf("save Keychain configuration: %w", err)
	}
	verified, err := keychain.Load()
	if err != nil {
		return fmt.Errorf("verify Keychain configuration: %w", err)
	}
	if err := verified.validate(); err != nil {
		return fmt.Errorf("validate verified Keychain configuration: %w", err)
	}
	if verified != old {
		return ErrConfigStoreMismatch
	}
	if err := legacy.Delete(); err != nil {
		return fmt.Errorf("remove migrated legacy configuration: %w", err)
	}
	return nil
}
