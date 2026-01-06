package cache

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/rs/zerolog/log"
)

type EncryptedStorage struct {
	db  *badger.DB
	key [32]byte
}

type EncryptedStorageOptions struct {
	// Only required if InMemory is false
	DBPath string
	// If InMemory is true, the database will be stored in memory and will never be persisted on disk
	InMemory bool

	// Only required if InMemory is false
	EncryptionKey [32]byte
}

func NewEncryptedStorage(opts EncryptedStorageOptions) (*EncryptedStorage, error) {

	var badgerOptions badger.Options

	if opts.InMemory {

		if opts.DBPath != "" {
			return nil, fmt.Errorf("DBPath must be empty if InMemory is true")
		}

		badgerOptions = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	} else {
		if opts.DBPath == "" {
			return nil, fmt.Errorf("DBPath must be set if InMemory is false")
		}

		badgerOptions = badger.DefaultOptions(opts.DBPath).WithLogger(nil)
	}

	db, err := badger.Open(badgerOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger: %w", err)
	}

	return &EncryptedStorage{
		db:  db,
		key: opts.EncryptionKey,
	}, nil
}

func (s *EncryptedStorage) GetAll() (map[string]interface{}, error) {
	result := make(map[string]interface{})

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := string(item.Key())

			var encrypted []byte
			encrypted, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("failed to copy value for key %s: %w", key, err)
			}

			decrypted, err := s.decrypt(encrypted)
			if err != nil {
				return fmt.Errorf("failed to decrypt value for key %s: %w", key, err)
			}

			var value interface{}
			if err := json.Unmarshal(decrypted, &value); err != nil {
				return fmt.Errorf("failed to unmarshal value for key %s: %w", key, err)
			}

			result[key] = value
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *EncryptedStorage) Set(key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	encrypted, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), encrypted)
	})
}

// Same as Set but with a TTL. Currently unused, but could be useful for proxying functionality in the future.
func (s *EncryptedStorage) SetWithTTL(key string, value interface{}, ttl time.Duration) error {

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	encrypted, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(key), encrypted).WithTTL(ttl)
		return txn.SetEntry(entry)
	})
}

func (s *EncryptedStorage) Get(key string, dest interface{}) error {

	var encrypted []byte

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		encrypted, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		return fmt.Errorf("get failed: %w", err)
	}

	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// if dest is a pointer to a pointer, allocate a new value and unmarshal the decrypted data into it.
	// without this it will fail to unmarshal if the destination is a pointer to a pointer
	rv := reflect.ValueOf(dest)
	if rv.Kind() == reflect.Ptr && rv.Elem().Kind() == reflect.Ptr {
		// Allocate new value
		newVal := reflect.New(rv.Elem().Type().Elem())
		if err := json.Unmarshal(decrypted, newVal.Interface()); err != nil {
			return err
		}
		rv.Elem().Set(newVal)
		return nil
	}

	return json.Unmarshal(decrypted, dest)
}

func (s *EncryptedStorage) Delete(key string) error {

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

func (s *EncryptedStorage) Close() error {
	return s.db.Close()
}

func (s *EncryptedStorage) ManualGarbageCollection() error {
	return s.db.RunValueLogGC(0.5) // 50% of the value log will be garbage collected
}

func (s *EncryptedStorage) StartPeriodicGarbageCollection(context context.Context) {

	// always run the garbage collection once on call
	err := s.ManualGarbageCollection()
	if err != nil && err != badger.ErrNoRewrite {
		log.Warn().Msgf("failed to run caching garbage collection: %v", err)
	}

	ticker := time.NewTicker(15 * time.Minute)
	go func() {

		for {
			select {
			case <-context.Done():
				return
			case <-ticker.C:
				err := s.db.RunValueLogGC(0.5) // 50% of the value log will be garbage collected
				if err != nil && err != badger.ErrNoRewrite {
					log.Warn().Msgf("failed to run caching garbage collection: %v", err)
				}
			}
		}
	}()
}

func (s *EncryptedStorage) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *EncryptedStorage) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
