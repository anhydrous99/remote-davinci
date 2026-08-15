//go:build !darwin || !cgo

package companion

func (KeychainConfigStore) Load() (Config, error) {
	return Config{}, ErrKeychainUnavailable
}

func (KeychainConfigStore) Save(Config) error {
	return ErrKeychainUnavailable
}

func (KeychainConfigStore) Delete() error {
	return ErrKeychainUnavailable
}
