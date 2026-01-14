/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/template"
	"time"

	"github.com/awnumar/memguard"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-resty/resty/v2"
	infisicalSdk "github.com/infisical/go-sdk"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/Infisical/infisical-merge/packages/util/cache"
	"github.com/spf13/cobra"
)

const DEFAULT_INFISICAL_CLOUD_URL = "https://app.infisical.com"

const CACHE_TYPE_KUBERNETES = "kubernetes"

const DYNAMIC_SECRET_LEASE_TEMPLATE = "dynamic-secret-lease-%s-%s-%s-%s-%s"

// duration to reduce from expiry of dynamic leases so that it gets triggered before expiry
const DYNAMIC_SECRET_PRUNE_EXPIRE_BUFFER = -15

// duration remove leases from the cache before they expire when the agent is first started with existing leases in the cache.
// if a lease is expired, or expires in 30 seconds or less, it will be deleted from the cache and a new lease will be created.
var CACHE_LEASE_EXPIRE_BUFFER = 30 * time.Second

const EXTERNAL_CA_INITIAL_POLLING_INTERVAL = 10 * time.Second
const EXTERNAL_CA_MAX_POLLING_INTERVAL = 1 * time.Hour
const DEFAULT_MONITORING_INTERVAL = 10 * time.Second

type PersistentCacheConfig struct {
	Type                    string `yaml:"type"`                       // file or kubernetes
	ServiceAccountTokenPath string `yaml:"service-account-token-path"` // relevant if type is kubernetes
	Path                    string `yaml:"path"`                       // where to store the cache
}

type CacheConfig struct {
	Persistent *PersistentCacheConfig `yaml:"persistent,omitempty"`
}

type DecryptedCache struct {
	Type        string `json:"type"` // currently only "access_token" is supported
	AccessToken string `json:"access_token"`
}

type CacheManager struct {
	cacheConfig  *CacheConfig
	cacheStorage *cache.EncryptedStorage

	IsEnabled      bool
	DecryptedCache DecryptedCache
}

type RetryConfig struct {
	MaxRetries int    `yaml:"max-retries"`
	BaseDelay  string `yaml:"base-delay"`
	MaxDelay   string `yaml:"max-delay"`
}

type Config struct {
	Version      string                   `yaml:"version,omitempty"`
	Infisical    InfisicalConfig          `yaml:"infisical"`
	Auth         AuthConfig               `yaml:"auth"`
	Sinks        []Sink                   `yaml:"sinks"`
	Cache        CacheConfig              `yaml:"cache,omitempty"`
	Templates    []Template               `yaml:"templates"`
	Certificates []AgentCertificateConfig `yaml:"certificates,omitempty"`
}

type TemplateWithID struct {
	ID       int
	Template Template
}

type CertificateWithID struct {
	ID          int
	Certificate AgentCertificateConfig
}

type CertificateState struct {
	CertificateID        string    `json:"certificate_id"`
	CertificateRequestID string    `json:"certificate_request_id,omitempty"`
	SerialNumber         string    `json:"serial_number"`
	CommonName           string    `json:"common_name"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	NextRenewalCheck     time.Time `json:"next_renewal_check"`
	Status               string    `json:"status"`
	LastError            string    `json:"last_error,omitempty"`
	RetryCount           int       `json:"retry_count"`
	LastRetry            time.Time `json:"last_retry,omitempty"`
}

type InfisicalConfig struct {
	Address                     string       `yaml:"address"`
	ExitAfterAuth               bool         `yaml:"exit-after-auth"`
	RevokeCredentialsOnShutdown bool         `yaml:"revoke-credentials-on-shutdown"`
	RetryConfig                 *RetryConfig `yaml:"retry-strategy,omitempty"`
}

type AuthConfig struct {
	Type   string      `yaml:"type"`
	Config interface{} `yaml:"config"`
}

type UniversalAuth struct {
	ClientIDPath             string `yaml:"client-id"`
	ClientSecretPath         string `yaml:"client-secret"`
	RemoveClientSecretOnRead bool   `yaml:"remove_client_secret_on_read"`
}

type KubernetesAuth struct {
	IdentityID          string `yaml:"identity-id"`
	ServiceAccountToken string `yaml:"service-account-token"`
}

type AzureAuth struct {
	IdentityID string `yaml:"identity-id"`
}

type GcpIdTokenAuth struct {
	IdentityID string `yaml:"identity-id"`
}

type GcpIamAuth struct {
	IdentityID        string `yaml:"identity-id"`
	ServiceAccountKey string `yaml:"service-account-key"`
}

type AwsIamAuth struct {
	IdentityID string `yaml:"identity-id"`
}

type LdapAuth struct {
	IdentityID           string `yaml:"identity-id"`
	LdapUsername         string `yaml:"username"`
	LdapPassword         string `yaml:"password"`
	RemovePasswordOnRead bool   `yaml:"remove-password-on-read"`
}

type Sink struct {
	Type   string      `yaml:"type"`
	Config SinkDetails `yaml:"config"`
}

type SinkDetails struct {
	Path string `yaml:"path"`
}

type Template struct {
	SourcePath            string `yaml:"source-path"`
	Base64TemplateContent string `yaml:"base64-template-content"`
	DestinationPath       string `yaml:"destination-path"`
	TemplateContent       string `yaml:"template-content"`

	Config struct { // Configurations for the template
		PollingInterval string `yaml:"polling-interval"` // How often to poll for changes in the secret
		Execute         struct {
			Command string `yaml:"command"` // Command to execute once the template has been rendered
			Timeout int64  `yaml:"timeout"` // Timeout for the command
		} `yaml:"execute"` // Command to execute once the template has been rendered
	} `yaml:"config"`
}

type CertificateLifecycleConfig struct {
	RenewBeforeExpiry    string `yaml:"renew-before-expiry"`
	StatusCheckInterval  string `yaml:"status-check-interval"`
	FailureRetryInterval string `yaml:"failure-retry-interval,omitempty"`
	MaxFailureRetries    int    `yaml:"max-failure-retries,omitempty"`
}

type CertificateAttributes struct {
	CommonName           string   `yaml:"common-name,omitempty"`
	AltNames             []string `yaml:"alt-names,omitempty"`
	KeyAlgorithm         string   `yaml:"key-algorithm,omitempty"`
	SignatureAlgorithm   string   `yaml:"signature-algorithm,omitempty"`
	KeyUsages            []string `yaml:"key-usages,omitempty"`
	ExtendedKeyUsages    []string `yaml:"extended-key-usages,omitempty"`
	NotBefore            string   `yaml:"not-before,omitempty"`
	NotAfter             string   `yaml:"not-after,omitempty"`
	RemoveRootsFromChain bool     `yaml:"remove-roots-from-chain"`
	TTL                  string   `yaml:"ttl"`
}

type AgentCertificateConfig struct {
	ProjectName     string                 `yaml:"project-slug"`
	ProfileName     string                 `yaml:"profile-name"`
	ProfileID       string                 `yaml:"-"`
	DestinationPath string                 `yaml:"destination-path"`
	CSR             string                 `yaml:"csr,omitempty"`
	CSRPath         string                 `yaml:"csr-path,omitempty"`
	Attributes      *CertificateAttributes `yaml:"attributes,omitempty"`
	// Certificate lifecycle and monitoring configuration
	Lifecycle CertificateLifecycleConfig `yaml:"lifecycle"`
	PostHooks struct {
		OnIssuance struct {
			Command string `yaml:"command,omitempty"`
			Timeout int64  `yaml:"timeout,omitempty"`
		} `yaml:"on-issuance,omitempty"`
		OnRenewal struct {
			Command string `yaml:"command,omitempty"`
			Timeout int64  `yaml:"timeout,omitempty"`
		} `yaml:"on-renewal,omitempty"`
		OnFailure struct {
			Command string `yaml:"command,omitempty"`
			Timeout int64  `yaml:"timeout,omitempty"`
		} `yaml:"on-failure,omitempty"`
	} `yaml:"post-hooks,omitempty"`
	FileConfig struct {
		PrivateKey struct {
			Path       string `yaml:"path,omitempty"`
			Permission string `yaml:"permission,omitempty"`
		} `yaml:"private-key,omitempty"`
		Certificate struct {
			Path       string `yaml:"path,omitempty"`
			Permission string `yaml:"permission,omitempty"`
		} `yaml:"certificate,omitempty"`
		Chain struct {
			Path       string `yaml:"path,omitempty"`
			Permission string `yaml:"permission,omitempty"`
			OmitRoot   *bool  `yaml:"omit-root,omitempty"`
		} `yaml:"chain,omitempty"`
	} `yaml:"file-output,omitempty"`
}

type DynamicSecretLeaseWithTTL struct {
	LeaseID           string
	ExpireAt          time.Time
	Environment       string
	SecretPath        string
	Slug              string
	ProjectSlug       string
	Data              map[string]interface{}
	TemplateIDs       []int
	RequestedLeaseTTL string
}

func (c *CacheManager) WriteToCache(key string, value interface{}, ttl *time.Duration) error {

	if !c.IsEnabled {
		return nil
	}

	var err error

	if ttl != nil {
		if *ttl <= 0 {
			return fmt.Errorf("ttl must be greater than 0")
		}
		err = c.cacheStorage.SetWithTTL(key, value, *ttl)
	} else {
		err = c.cacheStorage.Set(key, value)
	}
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return fmt.Errorf("unable to write to cache: %v", err)
	}
	return nil
}

func (c *CacheManager) GetAllCacheEntries() (map[string]interface{}, error) {

	if c.cacheStorage == nil || !c.IsEnabled {
		return nil, nil
	}

	response, err := c.cacheStorage.GetAll()
	if err != nil {
		return nil, fmt.Errorf("unable to get all cache keys: %v", err)
	}
	return response, nil
}

func (c *CacheManager) ReadFromCache(key string, destination interface{}) error {
	err := c.cacheStorage.Get(key, destination)
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return fmt.Errorf("unable to read from cache: %v", err)
	}

	return nil
}

func (c *CacheManager) DeleteFromCache(key string) error {
	if !c.IsEnabled {
		return nil
	}
	err := c.cacheStorage.Delete(key)
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return fmt.Errorf("unable to delete from cache: %v", err)
	}
	return nil
}

func NewCacheManager(ctx context.Context, cacheConfig *CacheConfig) (*CacheManager, error) {

	if cacheConfig == nil || cacheConfig.Persistent == nil {
		log.Info().Msg("caching is disabled, continuing without caching.")
		return &CacheManager{
			IsEnabled:      false,
			DecryptedCache: DecryptedCache{},
			cacheConfig:    cacheConfig,
		}, nil
	}

	if cacheConfig.Persistent.Type != CACHE_TYPE_KUBERNETES {
		return &CacheManager{}, fmt.Errorf("unsupported cache type: %s", cacheConfig.Persistent.Type)
	}

	// try to read the service account token file
	serviceAccountToken, err := ReadFile(cacheConfig.Persistent.ServiceAccountTokenPath)
	if err != nil || len(serviceAccountToken) == 0 {
		return &CacheManager{}, fmt.Errorf("unable to read service account token: %v. Please ensure the file exists and is not empty", err)
	}

	hash := sha256.Sum256(serviceAccountToken)
	encryptionKey := memguard.NewBufferFromBytes(hash[:]) // the hash (source) is wiped after copied to the secure buffer

	defer encryptionKey.Destroy()

	cacheStorage, err := cache.NewEncryptedStorage(cache.EncryptedStorageOptions{
		DBPath:        cacheConfig.Persistent.Path,
		EncryptionKey: encryptionKey,
		InMemory:      false,
	})

	go cacheStorage.StartPeriodicGarbageCollection(ctx)

	if err != nil {
		return nil, fmt.Errorf("unable to create cache storage: %v", err)
	}

	return &CacheManager{
		IsEnabled:    true,
		cacheConfig:  cacheConfig,
		cacheStorage: cacheStorage,
	}, nil
}

type DynamicSecretLeaseManager struct {
	leases       []DynamicSecretLeaseWithTTL
	mutex        sync.Mutex
	cacheManager *CacheManager
	retryConfig  *infisicalSdk.RetryRequestsConfig
}

func (d *DynamicSecretLeaseManager) WriteLeaseToCache(lease *DynamicSecretLeaseWithTTL, requestedLeaseTTL string) {

	if d.cacheManager == nil || !d.cacheManager.IsEnabled {
		return
	}

	if lease == nil {
		return
	}

	cacheKey := fmt.Sprintf(
		DYNAMIC_SECRET_LEASE_TEMPLATE,
		lease.ProjectSlug,
		lease.Environment,
		lease.SecretPath,
		lease.Slug,
		requestedLeaseTTL,
	)

	ttl := time.Until(lease.ExpireAt)

	log.Info().Msgf("[cache]: writing dynamic secret lease to cache: [cache-key=%s] [entry-ttl=%s]", cacheKey, ttl.String())

	if err := d.cacheManager.WriteToCache(cacheKey, lease, &ttl); err != nil {
		log.Error().Msgf("[cache]: unable to write dynamic secret lease to cache because %v", err)
	} else {
		log.Info().Msgf("[cache]: dynamic secret lease written to cache: %s", cacheKey)
	}
}

func (d *DynamicSecretLeaseManager) ReadLeaseFromCache(projectSlug, environment, secretPath, slug string, requestedLeaseTTL string) *DynamicSecretLeaseWithTTL {

	if d.cacheManager == nil || !d.cacheManager.IsEnabled {
		return nil
	}

	cacheKey := fmt.Sprintf(DYNAMIC_SECRET_LEASE_TEMPLATE, projectSlug, environment, secretPath, slug, requestedLeaseTTL)
	var lease *DynamicSecretLeaseWithTTL
	err := d.cacheManager.ReadFromCache(cacheKey, &lease)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		log.Error().Msgf("[cache]: unable to read dynamic secret lease from cache because %v", err)
		return nil
	}
	return lease
}

func (d *DynamicSecretLeaseManager) DeleteLeaseFromCache(projectSlug, environment, secretPath, slug, requestedLeaseTTL string) error {
	if d.cacheManager == nil || !d.cacheManager.IsEnabled {
		return nil
	}

	cacheKey := fmt.Sprintf(DYNAMIC_SECRET_LEASE_TEMPLATE, projectSlug, environment, secretPath, slug, requestedLeaseTTL)
	err := d.cacheManager.DeleteFromCache(cacheKey)
	if err != nil {
		return fmt.Errorf("unable to delete lease from cache: %v", err)
	}
	return nil
}

func (d *DynamicSecretLeaseManager) DeleteUnusedLeasesFromCache() error {

	if d.cacheManager.IsEnabled {
		log.Info().Msgf("[cache]: deleting unused dynamic secret leases from cache")
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	allCacheKeys, err := d.cacheManager.GetAllCacheEntries()

	if err != nil {
		return fmt.Errorf("unable to get all cache entries: %v", err)
	}

	if allCacheKeys == nil {
		log.Debug().Msgf("[cache]: no cache entries found")
		return nil
	}

	var cachedLeases []DynamicSecretLeaseWithTTL
	for cacheKey, leaseData := range allCacheKeys {
		if strings.HasPrefix(cacheKey, "dynamic-secret-lease-") {
			// Marshal back to JSON and unmarshal into the correct type
			jsonData, err := json.Marshal(leaseData)
			if err != nil {
				log.Warn().Msgf("[cache]: failed to marshal cached lease data for key %s: %v", cacheKey, err)
				continue
			}

			var lease DynamicSecretLeaseWithTTL
			if err := json.Unmarshal(jsonData, &lease); err != nil {
				log.Warn().Msgf("[cache]: failed to unmarshal cached lease data for key %s: %v", cacheKey, err)
				continue
			}

			cachedLeases = append(cachedLeases, lease)
		}
	}

	log.Debug().Msgf("[cache]: found %d cached leases", len(cachedLeases))
	log.Debug().Msgf("[cache]: current active leases count: %d", len(d.leases))

	// now we need to check if any of the cached leases are not in the d.leases list. If they are not, we need to delete them from the cache.
	for _, cachedLease := range cachedLeases {
		log.Debug().Msgf(
			"[cache]: checking cached lease: [project=%s], [env=%s], [path=%s], [slug=%s]",
			cachedLease.ProjectSlug,
			cachedLease.Environment,
			cachedLease.SecretPath,
			cachedLease.Slug,
		)

		// check if a lease with the same configuration exists (not comparing LeaseID since that changes on refresh)
		found := slices.ContainsFunc(d.leases, func(s DynamicSecretLeaseWithTTL) bool {
			match := s.ProjectSlug == cachedLease.ProjectSlug &&
				s.Environment == cachedLease.Environment &&
				s.SecretPath == cachedLease.SecretPath &&
				s.Slug == cachedLease.Slug &&
				s.RequestedLeaseTTL == cachedLease.RequestedLeaseTTL

			if match {
				log.Debug().Msgf("[cache]: found matching active lease: [project=%s], [env=%s], [path=%s], [slug=%s]",
					s.ProjectSlug,
					s.Environment,
					s.SecretPath,
					s.Slug,
				)
			}
			return match
		})

		if !found {
			log.Info().Msgf(
				"[cache]: no matching active lease found, deleting cached lease: [lease-id=%s], [project=%s], [env=%s], [path=%s], [slug=%s]",
				cachedLease.LeaseID,
				cachedLease.ProjectSlug,
				cachedLease.Environment,
				cachedLease.SecretPath,
				cachedLease.Slug,
			)

			if err := d.DeleteLeaseFromCache(
				cachedLease.ProjectSlug,
				cachedLease.Environment,
				cachedLease.SecretPath,
				cachedLease.Slug,
				cachedLease.RequestedLeaseTTL,
			); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}
		}
	}

	return nil

}

func (d *DynamicSecretLeaseManager) Prune() {

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.leases = slices.DeleteFunc(d.leases, func(s DynamicSecretLeaseWithTTL) bool {
		shouldDelete := time.Now().After(s.ExpireAt.Add(DYNAMIC_SECRET_PRUNE_EXPIRE_BUFFER * time.Second))

		if shouldDelete {
			if err := d.DeleteLeaseFromCache(s.ProjectSlug, s.Environment, s.SecretPath, s.Slug, s.RequestedLeaseTTL); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}
		}
		return shouldDelete
	})
}

// AppendUnsafe can be used if you already hold the lock
func (d *DynamicSecretLeaseManager) AppendUnsafe(lease DynamicSecretLeaseWithTTL) {

	index := slices.IndexFunc(d.leases, func(s DynamicSecretLeaseWithTTL) bool {
		// match by configuration (project, env, path, slug, TTL) and same lease ID
		// this allows merging template IDs when the same lease is added multiple times
		if lease.SecretPath == s.SecretPath && lease.Environment == s.Environment && lease.ProjectSlug == s.ProjectSlug && lease.Slug == s.Slug && lease.LeaseID == s.LeaseID && lease.RequestedLeaseTTL == s.RequestedLeaseTTL {
			return true
		}
		return false
	})

	if index != -1 {
		// merge template IDs, avoiding duplicates
		for _, newTemplateID := range lease.TemplateIDs {
			if !slices.Contains(d.leases[index].TemplateIDs, newTemplateID) {
				d.leases[index].TemplateIDs = append(d.leases[index].TemplateIDs, newTemplateID)
			}
		}
		return
	}

	d.leases = append(d.leases, lease)

	d.WriteLeaseToCache(&lease, lease.RequestedLeaseTTL)

}

// Expects a lock to be held before invocation
func (d *DynamicSecretLeaseManager) RegisterTemplateUnsafe(projectSlug, environment, secretPath, slug string, templateId int, requestedLeaseTTL string) {

	index := slices.IndexFunc(d.leases, func(lease DynamicSecretLeaseWithTTL) bool {
		// find lease by configuration, not by template ID
		// this allows us to register new template IDs to existing leases
		return lease.SecretPath == secretPath && lease.Environment == environment && lease.ProjectSlug == projectSlug && lease.Slug == slug && lease.RequestedLeaseTTL == requestedLeaseTTL
	})

	log.Debug().Msgf("\n[cache]: registering template [template-id=%d] for lease [project=%s], [env=%s], [path=%s], [slug=%s]\nIndex: %d", templateId, projectSlug, environment, secretPath, slug, index)
	if index != -1 {
		log.Debug().Msgf("Lease: %+v", d.leases[index])
	} else {
		log.Debug().Msgf("No lease found for the given configuration")
	}

	if index != -1 {
		// only add template ID if it's not already present
		if !slices.Contains(d.leases[index].TemplateIDs, templateId) {
			log.Debug().Msgf("Adding template ID %d to lease", templateId)
			d.leases[index].TemplateIDs = append(d.leases[index].TemplateIDs, templateId)
			d.WriteLeaseToCache(&d.leases[index], d.leases[index].RequestedLeaseTTL)
		} else {
			log.Debug().Msgf("Template ID %d already exists for lease, skipping", templateId)
		}
	}
}

// Expects a lock to be held before invocation
func (d *DynamicSecretLeaseManager) GetLeaseUnsafe(accessToken, projectSlug, environment, secretPath, slug string, templateId int, requestedLeaseTTL string) *DynamicSecretLeaseWithTTL {
	// first try to get from in-memory storage

	// find lease by configuration (project, env, path, slug, TTL) regardless of template IDs
	// this allows multiple templates to share the same lease
	for i := range d.leases {
		lease := &d.leases[i]
		if lease.SecretPath == secretPath && lease.Environment == environment && lease.ProjectSlug == projectSlug && lease.Slug == slug && lease.RequestedLeaseTTL == requestedLeaseTTL {
			log.Debug().Msgf("[cache]: lease found in in-memory storage: [project=%s], [env=%s], [path=%s], [slug=%s]", projectSlug, environment, secretPath, slug)
			return lease
		}
	}

	// if no lease is found in in-memory storage, try to get from cache
	leaseFromCache := d.ReadLeaseFromCache(projectSlug, environment, secretPath, slug, requestedLeaseTTL)

	if leaseFromCache == nil {
		log.Info().Msgf("[cache]: cache miss, no lease found [template-id=%d]", templateId)
	} else {
		log.Debug().Msgf("[cache]: cache hit, lease found [template-id=%d]", templateId)
	}

	log.Debug().Msgf("[cache]: lease from cache: %+v", leaseFromCache)

	if leaseFromCache != nil {

		// try to get the lease from the API
		dynamicSecretLease, err := util.GetDynamicSecretLease(accessToken, leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.LeaseID)
		if err != nil {

			log.Warn().Msgf("[cache]: error: %+v", err)

			// lease not found in API, delete it from cache and return nil
			if errors.Is(err, api.ErrNotFound) {
				log.Warn().Msgf("dynamic secret lease does not exist, deleting from cache: [lease-id=%s]", leaseFromCache.LeaseID)
				if err := d.DeleteLeaseFromCache(leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.Slug, leaseFromCache.RequestedLeaseTTL); err != nil {
					log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
				}

				return nil
			}

			// lease is found in cache but not in the the API, and the API returned a non 404-error. We should attempt to revoke it
			// at this point we know that we should be able to reach the API because we've done authentication successfully
			log.Warn().Msgf("unable to get dynamic secret lease from API. Revoking lease from cache: [lease-id=%s]", leaseFromCache.LeaseID)
			if err := d.DeleteLeaseFromCache(leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.Slug, leaseFromCache.RequestedLeaseTTL); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}

			if err := revokeDynamicSecretLease(accessToken, leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.LeaseID, d.retryConfig); err != nil {
				log.Warn().Msgf("unable to revoke dynamic secret lease %s: %v", leaseFromCache.LeaseID, err)
				return nil
			}

			return nil
		}

		// lease is expired or about to expire, delete from cache and attempt to revoke it
		if dynamicSecretLease.Lease.ExpireAt.Before(time.Now().Add(CACHE_LEASE_EXPIRE_BUFFER)) {
			log.Warn().Msgf("dynamic secret lease is expired or about to expire, deleting from cache: [lease-id=%s]", leaseFromCache.LeaseID)
			if err := d.DeleteLeaseFromCache(leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.Slug, leaseFromCache.RequestedLeaseTTL); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}

			if err := revokeDynamicSecretLease(accessToken, leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.LeaseID, d.retryConfig); err != nil {
				log.Warn().Msgf("unable to revoke expired dynamic secret lease %s: %v. Non-critical, the lease is already expired or will expire automatically within the next 2 minutes.", leaseFromCache.LeaseID, err)
				return nil
			}

			return nil
		}

		// we call appendUnsafe because we already hold the lock, and if we call Append directly we'll get a deadlock
		d.AppendUnsafe(*leaseFromCache)

		return leaseFromCache
	}

	return nil
}

// for a given template find the first expiring lease
// The bool indicates whether it contains valid expiry list
func (d *DynamicSecretLeaseManager) GetFirstExpiringLeaseTime() (time.Time, bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if len(d.leases) == 0 {
		return time.Time{}, false
	}

	var firstExpiry time.Time
	for i, el := range d.leases {
		if i == 0 {
			firstExpiry = el.ExpireAt
		}
		newLeaseTime := el.ExpireAt.Add(DYNAMIC_SECRET_PRUNE_EXPIRE_BUFFER * time.Second)
		if newLeaseTime.Before(firstExpiry) {
			firstExpiry = newLeaseTime
		}
	}
	return firstExpiry, true
}

func NewDynamicSecretLeaseManager(cacheManager *CacheManager, retryConfig *infisicalSdk.RetryRequestsConfig) *DynamicSecretLeaseManager {
	manager := &DynamicSecretLeaseManager{
		cacheManager: cacheManager,
		retryConfig:  retryConfig,
	}
	return manager
}

func ReadFile(filePath string) ([]byte, error) {
	return ioutil.ReadFile(filePath)
}

func ExecuteCommandWithTimeout(command string, timeout int64) error {

	shell := [2]string{"sh", "-c"}
	if runtime.GOOS == "windows" {
		shell = [2]string{"cmd", "/C"}
	} else {
		currentShell := os.Getenv("SHELL")
		if currentShell != "" {
			shell[0] = currentShell
		}
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, shell[0], shell[1], command)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok { // type assertion
			if exitError.ProcessState.ExitCode() == -1 {
				return fmt.Errorf("command timed out")
			}
		}
		return err
	} else {
		return nil
	}
}

func FileExists(filepath string) bool {
	info, err := os.Stat(filepath)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// WriteToFile writes data to the specified file path.
func WriteBytesToFile(data *bytes.Buffer, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = outputFile.Write(data.Bytes())
	return err
}

func ParseAuthConfig(authConfigFile []byte, destination interface{}) error {
	if err := yaml.Unmarshal(authConfigFile, destination); err != nil {
		return err
	}

	return nil
}

func validateAgentConfigVersionCompatibility(config *Config) error {
	return validateAgentConfigVersionCompatibilityWithMode(config, false)
}

func validateAgentConfigVersionCompatibilityWithMode(config *Config, isCertManagerMode bool) error {
	if config.Version == "" {
		if len(config.Certificates) > 0 {
			return fmt.Errorf("certificates are configured but 'version' field is not specified. Add 'version: v1' to your config")
		}
		return nil
	}

	switch config.Version {
	case "v1":
		if isCertManagerMode {
			return validateCertificateManagementV1ForCertManager(config)
		} else {
			return validateCertificateManagementV1(config)
		}
	default:
		return fmt.Errorf("unsupported version: %s. Supported versions: v1", config.Version)
	}
}

func validateCertificateManagementV1(config *Config) error {
	return fmt.Errorf("version: v1 is for certificate management. Please use 'infisical cert-manager agent' for certificate configurations")
}

func validateCertificateManagementV1ForCertManager(config *Config) error {
	if len(config.Certificates) == 0 {
		return fmt.Errorf("certificate management requires at least one certificate to be configured")
	}
	return nil
}

func ParseAgentConfig(configFile []byte) (*Config, error) {
	return parseAgentConfigWithMode(configFile, false)
}

func ParseAgentConfigForCertManager(configFile []byte) (*Config, error) {
	return parseAgentConfigWithMode(configFile, true)
}

func parseAgentConfigWithMode(configFile []byte, isCertManagerMode bool) (*Config, error) {
	var rawConfig Config

	if err := yaml.Unmarshal(configFile, &rawConfig); err != nil {
		return nil, err
	}

	// Set defaults
	if rawConfig.Infisical.Address == "" {
		rawConfig.Infisical.Address = DEFAULT_INFISICAL_CLOUD_URL
	}

	if rawConfig.Cache.Persistent != nil && rawConfig.Cache.Persistent.Type == CACHE_TYPE_KUBERNETES {
		if rawConfig.Cache.Persistent.ServiceAccountTokenPath == "" {
			rawConfig.Cache.Persistent.ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
	}

	config.INFISICAL_URL = util.AppendAPIEndpoint(rawConfig.Infisical.Address)

	log.Info().Msgf("Infisical instance address set to %s", rawConfig.Infisical.Address)

	if err := validateAgentConfigVersionCompatibilityWithMode(&rawConfig, isCertManagerMode); err != nil {
		return nil, err
	}

	return &rawConfig, nil
}

type secretArguments struct {
	IsRecursive                  bool  `json:"recursive"`
	ShouldExpandSecretReferences *bool `json:"expandSecretReferences,omitempty"`
}

func (s *secretArguments) SetDefaults() {
	if s.ShouldExpandSecretReferences == nil {
		var bool = true
		s.ShouldExpandSecretReferences = &bool
	}
}

func secretTemplateFunction(accessToken string, currentEtag *string) func(string, string, string, ...string) ([]models.SingleEnvironmentVariable, error) {
	// ...string is because golang doesn't have optional arguments.
	// thus we make it slice and pick it only first element
	return func(projectID, envSlug, secretPath string, args ...string) ([]models.SingleEnvironmentVariable, error) {
		var parsedArguments secretArguments
		// to make it optional
		if len(args) > 0 {
			err := json.Unmarshal([]byte(args[0]), &parsedArguments)
			if err != nil {
				return nil, err
			}
		}

		parsedArguments.SetDefaults()

		res, err := util.GetPlainTextSecretsV3(accessToken, projectID, envSlug, secretPath, true, parsedArguments.IsRecursive, "", *parsedArguments.ShouldExpandSecretReferences)
		if err != nil {
			return nil, err
		}

		*currentEtag = res.Etag

		return res.Secrets, nil
	}
}

func getSingleSecretTemplateFunction(accessToken string, currentEtag *string) func(string, string, string, string) (models.SingleEnvironmentVariable, error) {
	return func(projectID, envSlug, secretPath, secretName string) (models.SingleEnvironmentVariable, error) {
		secret, etag, err := util.GetSinglePlainTextSecretByNameV3(accessToken, projectID, envSlug, secretPath, secretName)
		if err != nil {
			return models.SingleEnvironmentVariable{}, err
		}
		*currentEtag = etag

		return secret, nil
	}
}

func dynamicSecretTemplateFunction(accessToken string, dynamicSecretManager *DynamicSecretLeaseManager, agentManager *AgentManager, templateId int, currentEtag *string) func(...string) (map[string]interface{}, error) {

	return func(args ...string) (map[string]interface{}, error) {
		dynamicSecretManager.mutex.Lock()
		defer dynamicSecretManager.mutex.Unlock()

		argLength := len(args)
		if argLength != 4 && argLength != 5 {
			return nil, fmt.Errorf("invalid arguments found for dynamic-secret function. Check template %d", templateId)
		}

		projectSlug, envSlug, secretPath, slug, ttl := args[0], args[1], args[2], args[3], ""
		if argLength == 5 {
			ttl = args[4]
		}

		dynamicSecretData := dynamicSecretManager.GetLeaseUnsafe(accessToken, projectSlug, envSlug, secretPath, slug, templateId, ttl)

		// if a lease is found (either in memory or in cache), we register the template and return the data
		if dynamicSecretData != nil {
			dynamicSecretManager.RegisterTemplateUnsafe(projectSlug, envSlug, secretPath, slug, templateId, ttl)

			etagData := fmt.Sprintf("%s-%s-%s-%s-%s", projectSlug, envSlug, secretPath, slug, ttl)
			dynamicSecretDataBytes, err := json.Marshal(dynamicSecretData.Data)
			if err != nil {
				return nil, err
			}
			hexEncodedData := hex.EncodeToString(dynamicSecretDataBytes)

			etag := sha256.Sum256([]byte(fmt.Sprintf("%s-%s", etagData, hexEncodedData)))
			*currentEtag = hex.EncodeToString(etag[:])

			return dynamicSecretData.Data, nil
		}

		temporaryInfisicalClient := infisicalSdk.NewInfisicalClient(context.Background(), infisicalSdk.Config{
			SiteUrl:             config.INFISICAL_URL,
			UserAgent:           api.USER_AGENT,
			AutoTokenRefresh:    false,
			RetryRequestsConfig: agentManager.SdkRetryConfig(),
		})
		temporaryInfisicalClient.Auth().SetAccessToken(accessToken)

		// if there's no lease (either in memory or in cache), we create a new lease

		leaseData, _, res, err := temporaryInfisicalClient.DynamicSecrets().Leases().Create(infisicalSdk.CreateDynamicSecretLeaseOptions{
			DynamicSecretName: slug,
			ProjectSlug:       projectSlug,
			EnvironmentSlug:   envSlug,
			SecretPath:        secretPath,
			TTL:               ttl,
		})

		if err != nil {
			return nil, err
		}

		dynamicSecretManager.AppendUnsafe(DynamicSecretLeaseWithTTL{LeaseID: res.Id, ExpireAt: res.ExpireAt, Environment: envSlug, SecretPath: secretPath, Slug: slug, ProjectSlug: projectSlug, Data: leaseData, TemplateIDs: []int{templateId}, RequestedLeaseTTL: ttl})

		return leaseData, nil
	}
}

func ProcessTemplate(templateId int, templatePath string, data interface{}, accessToken string, currentEtag *string, dynamicSecretManager *DynamicSecretLeaseManager, agentManager *AgentManager) (*bytes.Buffer, error) {

	// custom template function to fetch secrets from Infisical
	secretFunction := secretTemplateFunction(accessToken, currentEtag)
	dynamicSecretFunction := dynamicSecretTemplateFunction(accessToken, dynamicSecretManager, agentManager, templateId, currentEtag)
	getSingleSecretFunction := getSingleSecretTemplateFunction(accessToken, currentEtag)
	funcs := template.FuncMap{
		"secret":          secretFunction, // depreciated
		"listSecrets":     secretFunction,
		"dynamic_secret":  dynamicSecretFunction,
		"getSecretByName": getSingleSecretFunction,
		"minus": func(a, b int) int {
			return a - b
		},
		"add": func(a, b int) int {
			return a + b
		},
	}

	templateName := path.Base(templatePath)
	tmpl, err := template.New(templateName).Funcs(funcs).ParseFiles(templatePath)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return &buf, nil
}

func ProcessBase64Template(templateId int, encodedTemplate string, data interface{}, accessToken string, currentEtag *string, dynamicSecretLeaseManager *DynamicSecretLeaseManager, agentManager *AgentManager) (*bytes.Buffer, error) {
	// custom template function to fetch secrets from Infisical
	decoded, err := base64.StdEncoding.DecodeString(encodedTemplate)
	if err != nil {
		return nil, err
	}

	templateString := string(decoded)

	secretFunction := secretTemplateFunction(accessToken, currentEtag) // TODO: Fix this
	dynamicSecretFunction := dynamicSecretTemplateFunction(accessToken, dynamicSecretLeaseManager, agentManager, templateId, currentEtag)
	getSingleSecretFunction := getSingleSecretTemplateFunction(accessToken, currentEtag)
	funcs := template.FuncMap{
		"secret":          secretFunction,
		"dynamic_secret":  dynamicSecretFunction,
		"getSecretByName": getSingleSecretFunction,
	}

	templateName := "base64Template"

	tmpl, err := template.New(templateName).Funcs(funcs).Parse(templateString)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return &buf, nil
}

func ProcessLiteralTemplate(templateId int, templateString string, data interface{}, accessToken string, currentEtag *string, dynamicSecretLeaseManager *DynamicSecretLeaseManager, agentManager *AgentManager) (*bytes.Buffer, error) {

	secretFunction := secretTemplateFunction(accessToken, currentEtag)
	dynamicSecretFunction := dynamicSecretTemplateFunction(accessToken, dynamicSecretLeaseManager, agentManager, templateId, currentEtag)
	getSingleSecretFunction := getSingleSecretTemplateFunction(accessToken, currentEtag)
	funcs := template.FuncMap{
		"secret":          secretFunction,
		"dynamic_secret":  dynamicSecretFunction,
		"getSecretByName": getSingleSecretFunction,
	}

	templateName := "literalTemplate"

	tmpl, err := template.New(templateName).Funcs(funcs).Parse(templateString)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return &buf, nil
}

type AgentManager struct {
	accessToken                     string
	accessTokenTTL                  time.Duration
	accessTokenMaxTTL               time.Duration
	accessTokenFetchedTime          time.Time
	accessTokenRefreshedTime        time.Time
	mutex                           sync.Mutex
	filePaths                       []Sink // Store file paths if needed
	templates                       []TemplateWithID
	certificates                    []CertificateWithID
	certificateStates               map[int]*CertificateState
	dynamicSecretLeases             *DynamicSecretLeaseManager
	cacheManager                    *CacheManager
	authConfigBytes                 []byte
	authStrategy                    util.AuthStrategyType
	retryConfig                     *RetryConfig
	newAccessTokenNotificationChan  chan bool
	cachedUniversalAuthClientSecret string
	templateFirstRenderOnce         map[int]*sync.Once // Track first render per template
	certificateFirstIssueOnce       map[int]*sync.Once // Track first issue per certificate
	exitAfterAuth                   bool
	revokeCredentialsOnShutdown     bool

	isShuttingDown bool

	infisicalClient infisicalSdk.InfisicalClientInterface
	cancelContext   context.CancelFunc
}

type NewAgentMangerOptions struct {
	FileDeposits []Sink
	Templates    []Template
	Certificates []AgentCertificateConfig
	RetryConfig  *RetryConfig

	AuthConfigBytes []byte
	AuthStrategy    util.AuthStrategyType

	NewAccessTokenNotificationChan chan bool
	ExitAfterAuth                  bool
	RevokeCredentialsOnShutdown    bool
}

func NewAgentManager(options NewAgentMangerOptions) *AgentManager {
	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		util.HandleError(err, "Unable to get custom headers")
	}

	templates := make([]TemplateWithID, len(options.Templates))
	templateFirstRenderOnce := make(map[int]*sync.Once)
	for i, template := range options.Templates {
		templates[i] = TemplateWithID{ID: i + 1, Template: template}
		templateFirstRenderOnce[i+1] = &sync.Once{}
	}

	certificates := make([]CertificateWithID, len(options.Certificates))
	certificateStates := make(map[int]*CertificateState)
	certificateFirstIssueOnce := make(map[int]*sync.Once)
	for i, certificate := range options.Certificates {
		certificates[i] = CertificateWithID{ID: i + 1, Certificate: certificate}
		certificateStates[i+1] = &CertificateState{
			Status: "pending",
		}
		certificateFirstIssueOnce[i+1] = &sync.Once{}
	}

	agentManager := &AgentManager{
		filePaths:                 options.FileDeposits,
		templates:                 templates,
		certificates:              certificates,
		certificateStates:         certificateStates,
		certificateFirstIssueOnce: certificateFirstIssueOnce,

		authConfigBytes: options.AuthConfigBytes,
		authStrategy:    options.AuthStrategy,
		retryConfig:     options.RetryConfig,

		newAccessTokenNotificationChan: options.NewAccessTokenNotificationChan,
		exitAfterAuth:                  options.ExitAfterAuth,
		revokeCredentialsOnShutdown:    options.RevokeCredentialsOnShutdown,
		templateFirstRenderOnce:        templateFirstRenderOnce,
	}

	retryConfig := agentManager.SdkRetryConfig()

	ctx, cancelContext := context.WithCancel(context.Background())

	agentManager.infisicalClient = infisicalSdk.NewInfisicalClient(ctx, infisicalSdk.Config{
		SiteUrl:             config.INFISICAL_URL,
		UserAgent:           api.USER_AGENT, // ? Should we perhaps use a different user agent for the Agent for better analytics?
		AutoTokenRefresh:    true,
		CustomHeaders:       customHeaders,
		RetryRequestsConfig: retryConfig,
	})

	agentManager.cancelContext = cancelContext

	return agentManager
}

func (tm *AgentManager) SetToken(token string, accessTokenTTL time.Duration, accessTokenMaxTTL time.Duration) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tm.accessToken = token
	tm.accessTokenTTL = accessTokenTTL
	tm.accessTokenMaxTTL = accessTokenMaxTTL

	tm.newAccessTokenNotificationChan <- true
}

func (tm *AgentManager) GetToken() string {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	return tm.accessToken
}

func (tm *AgentManager) getTokenUnsafe() string {
	return tm.accessToken
}

func (tm *AgentManager) FetchUniversalAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, e error) {

	var universalAuthConfig UniversalAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &universalAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	clientID, err := util.GetEnvVarOrFileContent(util.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID_NAME, universalAuthConfig.ClientIDPath)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get client id: %v", err)
	}

	clientSecret, err := util.GetEnvVarOrFileContent("INFISICAL_UNIVERSAL_CLIENT_SECRET", universalAuthConfig.ClientSecretPath)
	if err != nil {
		if len(tm.cachedUniversalAuthClientSecret) == 0 {
			return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get client secret: %v", err)
		}
		clientSecret = tm.cachedUniversalAuthClientSecret
	}

	tm.cachedUniversalAuthClientSecret = clientSecret
	if universalAuthConfig.RemoveClientSecretOnRead {
		defer os.Remove(universalAuthConfig.ClientSecretPath)
	}

	log.Debug().Msgf("calling UniversalAuthLogin with clientID: %s", clientID)
	result, err := tm.infisicalClient.Auth().UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		log.Error().Msgf("UniversalAuthLogin failed: %v", err)
		return infisicalSdk.MachineIdentityCredential{}, err
	}
	log.Debug().Msg("UniversalAuthLogin succeeded")
	return result, nil
}

func (tm *AgentManager) FetchKubernetesAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, err error) {

	var kubernetesAuthConfig KubernetesAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &kubernetesAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	identityId, err := util.GetEnvVarOrFileContent(util.INFISICAL_MACHINE_IDENTITY_ID_NAME, kubernetesAuthConfig.IdentityID)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get identity id: %v", err)
	}

	serviceAccountTokenPath := os.Getenv(util.INFISICAL_KUBERNETES_SERVICE_ACCOUNT_TOKEN_NAME)
	if serviceAccountTokenPath == "" {
		serviceAccountTokenPath = kubernetesAuthConfig.ServiceAccountToken
		if serviceAccountTokenPath == "" {
			serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}
	}

	return tm.infisicalClient.Auth().KubernetesAuthLogin(identityId, serviceAccountTokenPath)

}

func (tm *AgentManager) FetchAzureAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, err error) {

	var azureAuthConfig AzureAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &azureAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	identityId, err := util.GetEnvVarOrFileContent(util.INFISICAL_MACHINE_IDENTITY_ID_NAME, azureAuthConfig.IdentityID)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get identity id: %v", err)
	}

	return tm.infisicalClient.Auth().AzureAuthLogin(identityId, "")

}

func (tm *AgentManager) FetchGcpIdTokenAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, err error) {

	var gcpIdTokenAuthConfig GcpIdTokenAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &gcpIdTokenAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	identityId, err := util.GetEnvVarOrFileContent(util.INFISICAL_MACHINE_IDENTITY_ID_NAME, gcpIdTokenAuthConfig.IdentityID)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get identity id: %v", err)
	}

	return tm.infisicalClient.Auth().GcpIdTokenAuthLogin(identityId)

}

func (tm *AgentManager) FetchGcpIamAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, err error) {

	var gcpIamAuthConfig GcpIamAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &gcpIamAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	identityId, err := util.GetEnvVarOrFileContent(util.INFISICAL_MACHINE_IDENTITY_ID_NAME, gcpIamAuthConfig.IdentityID)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get identity id: %v", err)
	}

	serviceAccountKeyPath := os.Getenv(util.INFISICAL_GCP_IAM_SERVICE_ACCOUNT_KEY_FILE_PATH_NAME)
	if serviceAccountKeyPath == "" {
		// we don't need to read this file, because the service account key path is directly read inside the sdk
		serviceAccountKeyPath = gcpIamAuthConfig.ServiceAccountKey
		if serviceAccountKeyPath == "" {
			return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("gcp service account key path not found")
		}
	}

	return tm.infisicalClient.Auth().GcpIamAuthLogin(identityId, serviceAccountKeyPath)

}

func (tm *AgentManager) FetchAwsIamAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, err error) {

	var awsIamAuthConfig AwsIamAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &awsIamAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	identityId, err := util.GetEnvVarOrFileContent(util.INFISICAL_MACHINE_IDENTITY_ID_NAME, awsIamAuthConfig.IdentityID)

	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get identity id: %v", err)
	}

	return tm.infisicalClient.Auth().AwsIamAuthLogin(identityId)

}

func (tm *AgentManager) FetchLdapAuthAccessToken() (credential infisicalSdk.MachineIdentityCredential, err error) {
	var ldapAuthConfig LdapAuth
	if err := ParseAuthConfig(tm.authConfigBytes, &ldapAuthConfig); err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to parse auth config due to error: %v", err)
	}

	identityId, err := util.GetEnvVarOrFileContent(util.INFISICAL_MACHINE_IDENTITY_ID_NAME, ldapAuthConfig.IdentityID)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get identity id: %v", err)
	}

	username, err := util.GetEnvVarOrFileContent(util.INFISICAL_LDAP_USERNAME, ldapAuthConfig.LdapUsername)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get ldap username: %v", err)
	}

	password, err := util.GetEnvVarOrFileContent(util.INFISICAL_LDAP_PASSWORD, ldapAuthConfig.LdapPassword)
	if err != nil {
		return infisicalSdk.MachineIdentityCredential{}, fmt.Errorf("unable to get ldap password: %v", err)
	}

	if ldapAuthConfig.RemovePasswordOnRead {
		defer os.Remove(ldapAuthConfig.LdapPassword)
	}

	return tm.infisicalClient.Auth().LdapAuthLogin(identityId, username, password)
}

// Fetches a new access token using client credentials
func (tm *AgentManager) FetchNewAccessToken() error {
	log.Debug().Msgf("FetchNewAccessToken: starting with auth strategy %s", tm.authStrategy)
	authStrategies := map[util.AuthStrategyType]func() (credential infisicalSdk.MachineIdentityCredential, e error){
		util.AuthStrategy.UNIVERSAL_AUTH:    tm.FetchUniversalAuthAccessToken,
		util.AuthStrategy.KUBERNETES_AUTH:   tm.FetchKubernetesAuthAccessToken,
		util.AuthStrategy.AZURE_AUTH:        tm.FetchAzureAuthAccessToken,
		util.AuthStrategy.GCP_ID_TOKEN_AUTH: tm.FetchGcpIdTokenAuthAccessToken,
		util.AuthStrategy.GCP_IAM_AUTH:      tm.FetchGcpIamAuthAccessToken,
		util.AuthStrategy.AWS_IAM_AUTH:      tm.FetchAwsIamAuthAccessToken,
		util.AuthStrategy.LDAP_AUTH:         tm.FetchLdapAuthAccessToken,
	}

	if _, ok := authStrategies[tm.authStrategy]; !ok {
		return fmt.Errorf("auth strategy %s not found", tm.authStrategy)
	}

	log.Debug().Msg("FetchNewAccessToken: calling auth strategy")
	credential, err := authStrategies[tm.authStrategy]()

	if err != nil {
		log.Debug().Msgf("FetchNewAccessToken: auth strategy returned error: %v", err)
		return err
	}
	log.Debug().Msg("FetchNewAccessToken: auth strategy succeeded, processing token")

	accessTokenTTL := time.Duration(credential.ExpiresIn * int64(time.Second))
	accessTokenMaxTTL := time.Duration(credential.AccessTokenMaxTTL * int64(time.Second))

	if accessTokenTTL <= time.Duration(30)*time.Second {
		util.PrintErrorMessageAndExit("At this time, agent does not support refresh of tokens with 30 seconds or less ttl. Please increase access token ttl and try again")
	}

	tm.accessTokenFetchedTime = time.Now()

	log.Debug().Msg("FetchNewAccessToken: setting token")
	tm.SetToken(credential.AccessToken, accessTokenTTL, accessTokenMaxTTL)

	log.Debug().Msg("FetchNewAccessToken: completed successfully")
	return nil
}

func (tm *AgentManager) SdkRetryConfig() *infisicalSdk.RetryRequestsConfig {
	retryConfig := &infisicalSdk.RetryRequestsConfig{
		ExponentialBackoff: &infisicalSdk.ExponentialBackoffStrategy{
			BaseDelay:  200 * time.Millisecond,
			MaxDelay:   5 * time.Second,
			MaxRetries: 3,
		},
	}

	var baseDelay string
	var maxDelay string
	var maxRetries int

	if tm.retryConfig != nil {
		baseDelay = tm.retryConfig.BaseDelay
		maxDelay = tm.retryConfig.MaxDelay
		maxRetries = tm.retryConfig.MaxRetries
	}

	if envVarBaseDelay := os.Getenv(util.INFISICAL_RETRY_BASE_DELAY_NAME); envVarBaseDelay != "" {
		baseDelay = envVarBaseDelay
	}
	if envVarMaxDelay := os.Getenv(util.INFISICAL_RETRY_MAX_DELAY_NAME); envVarMaxDelay != "" {
		maxDelay = envVarMaxDelay
	}
	if envVarMaxRetries := os.Getenv(util.INFISICAL_RETRY_MAX_RETRIES_NAME); envVarMaxRetries != "" {
		maxRetriesInt, err := strconv.Atoi(envVarMaxRetries)
		if err != nil {
			log.Error().Msgf("unable to parse retry config max retries because %v", err)
			os.Exit(1)
		}

		maxRetries = maxRetriesInt
	}

	if baseDelay != "" {
		duration, err := util.ParseTimeDurationString(baseDelay, true)
		if err != nil {
			log.Error().Msgf("unable to parse retry config base delay because %v", err)
			os.Exit(1)
		}
		retryConfig.ExponentialBackoff.BaseDelay = duration
	}
	if maxDelay != "" {

		duration, err := util.ParseTimeDurationString(maxDelay, true)
		if err != nil {
			log.Error().Msgf("unable to parse retry config max delay because %v", err)
			os.Exit(1)
		}

		// MaxDelay is in milliseconds
		retryConfig.ExponentialBackoff.MaxDelay = duration
	}
	if maxRetries != 0 {
		retryConfig.ExponentialBackoff.MaxRetries = maxRetries
	}

	return retryConfig
}

func revokeDynamicSecretLease(accessToken, projectSlug, environment, secretPath, leaseID string, retryConfig *infisicalSdk.RetryRequestsConfig) error {
	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		return fmt.Errorf("unable to get custom headers: %v", err)
	}

	temporaryInfisicalClient := infisicalSdk.NewInfisicalClient(context.Background(), infisicalSdk.Config{
		SiteUrl:             config.INFISICAL_URL,
		UserAgent:           api.USER_AGENT,
		AutoTokenRefresh:    false,
		CustomHeaders:       customHeaders,
		RetryRequestsConfig: retryConfig,
	})

	temporaryInfisicalClient.Auth().SetAccessToken(accessToken)

	_, err = temporaryInfisicalClient.DynamicSecrets().Leases().DeleteById(infisicalSdk.DeleteDynamicSecretLeaseOptions{
		LeaseId:         leaseID,
		ProjectSlug:     projectSlug,
		SecretPath:      secretPath,
		EnvironmentSlug: environment,
	})
	if err != nil {
		return fmt.Errorf("unable to revoke dynamic secret lease: %v", err)
	}

	return nil

}

func (tm *AgentManager) RevokeCredentials() error {
	var token string

	log.Info().Msg("revoking credentials...")

	token = tm.GetToken()

	if token == "" {
		return fmt.Errorf("no access token found")
	}
	// lock the dynamic secret leases to prevent renewals during the revoke process
	tm.dynamicSecretLeases.mutex.Lock()
	defer tm.dynamicSecretLeases.mutex.Unlock()

	dynamicSecretLeases := tm.dynamicSecretLeases.leases

	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		return fmt.Errorf("unable to get custom headers: %v", err)
	}

	var revokedLeasesCount atomic.Int32
	revokedLeasesChan := make(chan bool, len(dynamicSecretLeases))

	for _, lease := range dynamicSecretLeases {

		go func(lease DynamicSecretLeaseWithTTL) {

			err := revokeDynamicSecretLease(token, lease.ProjectSlug, lease.Environment, lease.SecretPath, lease.LeaseID, tm.SdkRetryConfig())

			if err != nil {

				if strings.Contains(err.Error(), "status-code=404") {
					log.Info().Msgf("dynamic secret lease %s not found, skipping", lease.LeaseID)
				} else {
					log.Error().Msgf("unable to revoke dynamic secret lease %s: %v", lease.LeaseID, err)
				}
				// we always send to the revokedLeasesChan to prevent the main thread from waiting forever
				revokedLeasesChan <- true
				return
			}

			// write to the lease file, and make it an empty file
			var erasedTemplatePaths []string

			for _, template := range tm.templates {
				log.Debug().Msgf("template '%s' is associated with multiple templates. IDs: %v. deleting lease from template file: %s", template.Template.DestinationPath, lease.TemplateIDs, template.Template.DestinationPath)
				if slices.Contains(lease.TemplateIDs, template.ID) {
					if erasedTemplatePaths != nil && slices.Contains(erasedTemplatePaths, template.Template.DestinationPath) {
						log.Debug().Msgf("template '%s' already erased, skipping", template.Template.DestinationPath)
						continue
					}
					if _, err := os.Stat(template.Template.DestinationPath); !os.IsNotExist(err) {
						if err := os.WriteFile(template.Template.DestinationPath, []byte(""), 0644); err != nil {
							log.Warn().Msgf("unable to erase lease from file '%s' because %v", template.Template.DestinationPath, err)
						}
					}
					erasedTemplatePaths = append(erasedTemplatePaths, template.Template.DestinationPath)
				}
			}

			revokedLeasesChan <- true
			log.Info().Msgf("successfully revoked dynamic secret lease [id=%s] [project-slug=%s]", lease.LeaseID, lease.ProjectSlug)
		}(lease)
	}

	var shouldBreak atomic.Bool
	for {
		select {
		case <-revokedLeasesChan:
			revokedLeasesCount.Add(1)
			if revokedLeasesCount.Load() == int32(len(dynamicSecretLeases)) {
				shouldBreak.Store(true)
			}
		case <-time.After(5 * time.Minute):
			log.Warn().Msg("credential revocation timed out after 5 minutes, forcing exit")
			return fmt.Errorf("credential revocation timed out after 5 minutes")
		}

		if shouldBreak.Load() {
			log.Info().Msg("all dynamic secret leases have been revoked")
			break
		}
	}

	var deletedTokens []string

	for _, sink := range tm.filePaths {
		if sink.Type == "file" {
			tokenBytes, err := os.ReadFile(sink.Config.Path)
			if err != nil {
				log.Error().Msgf("unable to read token from file '%s' because %v", sink.Config.Path, err)
				continue
			}

			token := string(tokenBytes)
			if token != "" {
				log.Info().Msgf("revoking token from file '%s'", sink.Config.Path)

				temporaryInfisicalClient := infisicalSdk.NewInfisicalClient(context.Background(), infisicalSdk.Config{
					SiteUrl:          config.INFISICAL_URL,
					UserAgent:        api.USER_AGENT,
					AutoTokenRefresh: false,
					CustomHeaders:    customHeaders,
				})

				temporaryInfisicalClient.Auth().SetAccessToken(token)
				err := temporaryInfisicalClient.Auth().RevokeAccessToken()
				if err != nil {
					log.Error().Msgf("unable to revoke access token from file '%s' because %v", sink.Config.Path, err)
					continue
				}

				if _, err := os.Stat(sink.Config.Path); !os.IsNotExist(err) {
					if err := os.WriteFile(sink.Config.Path, []byte(""), 0644); err != nil {
						log.Warn().Msgf("unable to erase access token from file '%s' because %v", sink.Config.Path, err)
						continue
					}
				}

				log.Info().Msgf("successfully revoked access token from file '%s'", sink.Config.Path)

				deletedTokens = append(deletedTokens, token)
			}
		}
	}

	// check to see if the active token was already deleted, if not, delete it
	if !slices.Contains(deletedTokens, token) {
		temporaryInfisicalClient := infisicalSdk.NewInfisicalClient(context.Background(), infisicalSdk.Config{
			SiteUrl:          config.INFISICAL_URL,
			UserAgent:        api.USER_AGENT,
			AutoTokenRefresh: false,
			CustomHeaders:    customHeaders,
		})
		temporaryInfisicalClient.Auth().SetAccessToken(token)
		err := temporaryInfisicalClient.Auth().RevokeAccessToken()
		if err != nil {
			log.Error().Msgf("unable to revoke token because %v", err)
		}

		log.Info().Msgf("successfully revoked active access token")
		deletedTokens = append(deletedTokens, token)
	}

	log.Info().Msgf("successfully revoked %d access tokens", len(deletedTokens))

	return nil
}

// Refreshes the existing access token
func (tm *AgentManager) RefreshAccessToken(accessToken string) error {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return err
	}

	httpClient.SetRetryCount(10000).
		SetRetryMaxWaitTime(20 * time.Second).
		SetRetryWaitTime(5 * time.Second)

	response, err := api.CallMachineIdentityRefreshAccessToken(httpClient, api.UniversalAuthRefreshRequest{AccessToken: accessToken})
	if err != nil {
		return err
	}

	accessTokenTTL := time.Duration(response.AccessTokenTTL * int(time.Second))
	accessTokenMaxTTL := time.Duration(response.AccessTokenMaxTTL * int(time.Second))
	tm.accessTokenRefreshedTime = time.Now()

	tm.SetToken(response.AccessToken, accessTokenTTL, accessTokenMaxTTL)

	return nil
}

func (tm *AgentManager) ManageTokenLifecycle() {
	for {

		if tm.isShuttingDown {
			return
		}

		accessTokenMaxTTLExpiresInTime := tm.accessTokenFetchedTime.Add(tm.accessTokenMaxTTL - (5 * time.Second))
		accessTokenRefreshedTime := tm.accessTokenRefreshedTime

		if accessTokenRefreshedTime.IsZero() {
			accessTokenRefreshedTime = tm.accessTokenFetchedTime
		}

		if tm.accessTokenFetchedTime.IsZero() && tm.accessTokenRefreshedTime.IsZero() {
			// try to fetch token from sink files first
			// if token is found, refresh the token right away and continue from there
			isSavedTokenValid := false
			token := tm.FetchTokenFromFiles()
			if token != "" {

				log.Info().Msg("found existing token in file, attempting to refresh...")
				err := tm.RefreshAccessToken(token)
				isSavedTokenValid = err == nil

				if isSavedTokenValid {
					log.Info().Msg("token refreshed successfully from saved file")
					tm.accessTokenFetchedTime = time.Now()
				} else {
					log.Error().Msg("unable to refresh token from saved file")
				}
			}

			if !isSavedTokenValid {
				// case: init login to get access token
				log.Info().Msg("attempting to authenticate...")
				err := tm.FetchNewAccessToken()
				if err != nil {
					log.Error().Msgf("unable to authenticate because %v. Will retry in 30 seconds", err)

					// wait a bit before trying again
					time.Sleep((30 * time.Second))
					continue
				}
				log.Debug().Msgf("authentication successful, starting token lifecycle management with TTL: %s, Max TTL: %s", tm.accessTokenTTL, tm.accessTokenMaxTTL)
			}
		} else if time.Now().After(accessTokenMaxTTLExpiresInTime) {
			// case: token has reached max ttl and we should re-authenticate entirely (cannot refresh)
			log.Info().Msgf("token has reached max ttl, attempting to re authenticate...")
			err := tm.FetchNewAccessToken()
			if err != nil {
				log.Error().Msgf("unable to authenticate because %v. Will retry in 30 seconds", err)

				// wait a bit before trying again
				time.Sleep((30 * time.Second))
				continue
			}
		} else {
			// case: token ttl has expired, but the token is still within max ttl, so we can refresh
			log.Info().Msgf("attempting to refresh existing token...")
			err := tm.RefreshAccessToken(tm.GetToken())
			if err != nil {
				log.Error().Msgf("unable to refresh token because %v. Will retry in 30 seconds", err)

				// wait a bit before trying again
				time.Sleep((30 * time.Second))
				continue
			}
		}

		if accessTokenRefreshedTime.IsZero() {
			accessTokenRefreshedTime = tm.accessTokenFetchedTime
		} else {
			accessTokenRefreshedTime = tm.accessTokenRefreshedTime
		}

		// Recalculate next expiry time at 2/3 of the TTL
		nextAccessTokenExpiresInTime := accessTokenRefreshedTime.Add(tm.accessTokenTTL * 2 / 3)
		accessTokenMaxTTLExpiresInTime = tm.accessTokenFetchedTime.Add(tm.accessTokenMaxTTL - (5 * time.Second))

		if nextAccessTokenExpiresInTime.After(accessTokenMaxTTLExpiresInTime) {
			// case: Refreshed so close that the next refresh would occur beyond max ttl
			// Sleep until we're at 2/3 of the remaining time to max TTL
			remainingTime := time.Until(accessTokenMaxTTLExpiresInTime)
			time.Sleep(remainingTime * 2 / 3)
		} else {
			// Sleep until we're at 2/3 of the TTL
			sleepDuration := tm.accessTokenTTL * 2 / 3
			log.Debug().Msgf("sleeping for %s (2/3 of TTL %s) before next token refresh", sleepDuration, tm.accessTokenTTL)
			time.Sleep(sleepDuration)
		}
	}
}

func (tm *AgentManager) WriteTokenToFiles() {
	token := tm.GetToken()

	for _, sinkFile := range tm.filePaths {
		if sinkFile.Type == "file" {
			err := ioutil.WriteFile(sinkFile.Config.Path, []byte(token), 0644)
			if err != nil {
				log.Error().Msgf("unable to write file sink to path '%s' because %v", sinkFile.Config.Path, err)
			}

			log.Info().Msgf("new access token saved to file at path '%s'", sinkFile.Config.Path)

		} else {
			log.Error().Msg("unsupported sink type. Only 'file' type is supported")
		}
	}
}

func (tm *AgentManager) FetchTokenFromFiles() string {
	for _, sinkFile := range tm.filePaths {
		if sinkFile.Type == "file" {
			tokenBytes, err := ioutil.ReadFile(sinkFile.Config.Path)
			if err != nil {
				log.Debug().Msgf("unable to read token from file '%s' because %v", sinkFile.Config.Path, err)
				continue
			}

			token := string(tokenBytes)
			if token != "" {
				return token
			}
		}
	}
	return ""
}

func (tm *AgentManager) WriteTemplateToFile(bytes *bytes.Buffer, template *Template, templateId int) {
	if err := WriteBytesToFile(bytes, template.DestinationPath); err != nil {
		log.Error().Msgf("template engine: unable to write secrets to path because %s. Will try again on next cycle", err)
		return
	}
	if template.SourcePath != "" {
		log.Info().Msgf("template engine: secret template at path %s has been rendered and saved to path %s [template-id=%d]", template.SourcePath, template.DestinationPath, templateId)
	} else {
		log.Info().Msgf("template engine: secret template has been rendered and saved to path %s [template-id=%d]", template.DestinationPath, templateId)
	}
}

func (tm *AgentManager) MonitorSecretChanges(ctx context.Context, secretTemplate Template, templateId int, sigChan chan os.Signal, monitoringChan chan bool) {

	pollingInterval := time.Duration(5 * time.Minute)

	if secretTemplate.Config.PollingInterval != "" {
		interval, err := util.ParseTimeDurationString(secretTemplate.Config.PollingInterval, false)

		if err != nil {
			log.Error().Msgf("unable to convert polling interval to time because %v", err)
			sigChan <- syscall.SIGINT
			return

		} else {
			pollingInterval = interval
		}
	}

	var existingEtag string
	var currentEtag string
	var firstRun = true

	execTimeout := secretTemplate.Config.Execute.Timeout
	execCommand := secretTemplate.Config.Execute.Command

	for {
		select {
		case <-ctx.Done():
			return
		default:
			{

				tm.dynamicSecretLeases.Prune()
				token := tm.GetToken()

				if token != "" {
					if tm.isShuttingDown {
						return
					}

					var processedTemplate *bytes.Buffer
					var err error

					if secretTemplate.SourcePath != "" {
						processedTemplate, err = ProcessTemplate(templateId, secretTemplate.SourcePath, nil, token, &currentEtag, tm.dynamicSecretLeases, tm)
					} else if secretTemplate.TemplateContent != "" {
						processedTemplate, err = ProcessLiteralTemplate(templateId, secretTemplate.TemplateContent, nil, token, &currentEtag, tm.dynamicSecretLeases, tm)
					} else {
						processedTemplate, err = ProcessBase64Template(templateId, secretTemplate.Base64TemplateContent, nil, token, &currentEtag, tm.dynamicSecretLeases, tm)
					}

					if err != nil {
						log.Error().Msgf("unable to process template because %v [template-id=%d]", err, templateId)

						// case: if exit-after-auth is true, it should exit the agent once an error on secret fetching occurs with the appropriate exit code (1)
						// previous behavior would exit after 25 sec with status code 0, even if this step errors
						if tm.exitAfterAuth {
							os.Exit(1)
						}

						// if polling interval is less than 1 minute, we sleep for the polling interval, otherwise we sleep for 1 minute

						sleepDuration := 30 * time.Second

						if pollingInterval < sleepDuration {
							sleepDuration = pollingInterval
						}

						log.Info().Msgf("template engine: retrying in %s [template-id=%d]", sleepDuration.String(), templateId)
						time.Sleep(sleepDuration)
						continue

					} else {
						if (existingEtag != currentEtag) || firstRun {

							if existingEtag != currentEtag {
								log.Debug().Msgf("template engine: etag mismatch, re-rendering template [template-id=%d]", templateId)
								log.Debug().Msgf("processed template: %+v", processedTemplate)
							}

							tm.WriteTemplateToFile(processedTemplate, &secretTemplate, templateId)

							existingEtag = currentEtag

							if !firstRun && execCommand != "" {
								log.Info().Msgf("executing command: %s", execCommand)
								err := ExecuteCommandWithTimeout(execCommand, execTimeout)

								if err != nil {
									log.Error().Msgf("unable to execute command because %v", err)
								}

							}
							if firstRun {
								firstRun = false
								// Signal that this template has completed its first render
								tm.templateFirstRenderOnce[templateId].Do(func() {
									monitoringChan <- true
								})
							}
						}
					}

					// now the idea is we pick the next sleep time in which the one shorter out of
					// - polling time
					// - first lease that's gonna get expired in the template
					firstLeaseExpiry, isValid := tm.dynamicSecretLeases.GetFirstExpiringLeaseTime()
					var waitTime = pollingInterval
					if isValid && time.Until(firstLeaseExpiry) < pollingInterval {
						waitTime = time.Until(firstLeaseExpiry)
					}

					time.Sleep(waitTime)
				} else {
					// It fails to get the access token. So we will re-try in 3 seconds. We do this because if we don't, the user will have to wait for the next polling interval to get the first secret render.
					time.Sleep(3 * time.Second)
				}
			}
		}
	}
}

func parseDurationWithDays(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		if daysInt, err := strconv.Atoi(days); err == nil {
			return time.Duration(daysInt*24) * time.Hour, nil
		} else {
			return 0, fmt.Errorf("invalid days format: %s", s)
		}
	}
	return time.ParseDuration(s)
}

func processCertificateCSRPaths(certificates *[]AgentCertificateConfig) error {
	for i := range *certificates {
		cert := &(*certificates)[i]

		if cert.CSRPath != "" {
			if cert.CSR != "" {
				return fmt.Errorf("certificate configuration cannot specify both 'csr' and 'csr-path' fields")
			}

			csrBytes, err := os.ReadFile(cert.CSRPath)
			if err != nil {
				return fmt.Errorf("failed to read CSR file '%s': %v", cert.CSRPath, err)
			}

			cert.CSR = string(csrBytes)
		}
	}
	return nil
}

func validateCertificateLifecycleConfig(certificates *[]AgentCertificateConfig) error {
	for i, cert := range *certificates {
		if cert.Attributes == nil || cert.Attributes.TTL == "" || cert.Lifecycle.RenewBeforeExpiry == "" {
			continue
		}

		ttl := cert.Attributes.TTL
		commonName := cert.Attributes.CommonName
		altNames := cert.Attributes.AltNames

		ttlDuration, err := parseDurationWithDays(ttl)
		if err != nil {
			return fmt.Errorf("certificate %d: invalid TTL format '%s': %v", i+1, ttl, err)
		}

		renewBeforeDuration, err := parseDurationWithDays(cert.Lifecycle.RenewBeforeExpiry)
		if err != nil {
			return fmt.Errorf("certificate %d: invalid renew-before-expiry format '%s': %v", i+1, cert.Lifecycle.RenewBeforeExpiry, err)
		}

		if renewBeforeDuration >= ttlDuration {
			certName := "certificate"
			if commonName != "" {
				certName = fmt.Sprintf("certificate '%s'", commonName)
			} else if len(altNames) > 0 {
				certName = fmt.Sprintf("certificate '%s'", altNames[0])
			} else if cert.ProjectName != "" && cert.ProfileName != "" {
				certName = fmt.Sprintf("certificate '%s/%s'", cert.ProjectName, cert.ProfileName)
			}

			return fmt.Errorf("%s: renew-before-expiry (%v) must be less than TTL (%v). "+
				"Current configuration would attempt to renew the certificate before or immediately after it's issued, "+
				"which is not possible. Please adjust either the TTL or renew-before-expiry setting",
				certName, renewBeforeDuration, ttlDuration)
		}

		if renewBeforeDuration > time.Duration(float64(ttlDuration)*0.8) {
			certName := "certificate"
			if commonName != "" {
				certName = commonName
			}
			log.Warn().
				Str("certificate", certName).
				Dur("ttl", ttlDuration).
				Dur("renewBeforeExpiry", renewBeforeDuration).
				Msg("renew-before-expiry is more than 80% of TTL, which may result in very frequent renewal attempts")
		}
	}
	return nil
}

func resolveCertificateNameReferences(certificates *[]AgentCertificateConfig, httpClient *resty.Client) error {
	for i := range *certificates {
		cert := &(*certificates)[i]

		if cert.ProjectName == "" || cert.ProfileName == "" {
			return fmt.Errorf("certificate configuration must specify both 'project-slug' and 'profile-name'")
		}

		project, err := api.CallGetProjectBySlug(httpClient, cert.ProjectName)
		if err != nil {
			return fmt.Errorf("failed to resolve project name '%s': %v. Please check that the project exists and you have access to it", cert.ProjectName, err)
		}

		if project.ID == "" {
			return fmt.Errorf("project '%s' was found but returned empty ID. This may indicate a server issue", cert.ProjectName)
		}

		profile, err := api.CallGetCertificateProfileBySlug(httpClient, project.ID, cert.ProfileName)
		if err != nil {
			return fmt.Errorf("failed to resolve profile name '%s' in project '%s' (project ID: %s): %v. Please check that the certificate profile exists in this project", cert.ProfileName, cert.ProjectName, project.ID, err)
		}

		cert.ProfileID = profile.ID
	}
	return nil
}

func (tm *AgentManager) getCertificateTTL(certificate *AgentCertificateConfig) string {
	if certificate.Attributes != nil {
		return certificate.Attributes.TTL
	}
	return ""
}

func (tm *AgentManager) getCertificateDisplayName(certificateId int, certificate *AgentCertificateConfig) string {
	if certificate.Attributes != nil {
		if certificate.Attributes.CommonName != "" {
			return certificate.Attributes.CommonName
		}
		if len(certificate.Attributes.AltNames) > 0 {
			return certificate.Attributes.AltNames[0]
		}
	}
	if certificate.CSRPath != "" {
		return fmt.Sprintf("CSR-based certificate (%s)", certificate.CSRPath)
	}
	return fmt.Sprintf("certificate %d", certificateId)
}

func buildCertificateAttributes(certificate *AgentCertificateConfig) *api.CertificateAttributes {
	if certificate.Attributes == nil {
		return nil
	}

	attributes := &api.CertificateAttributes{}
	hasAny := false
	certAttrs := certificate.Attributes

	setString := func(dst *string, src string) {
		if src != "" {
			*dst = src
			hasAny = true
		}
	}
	setStringSlice := func(dst *[]string, src []string) {
		if len(src) > 0 {
			*dst = src
			hasAny = true
		}
	}

	setString(&attributes.TTL, certAttrs.TTL)
	setString(&attributes.CommonName, certAttrs.CommonName)
	setString(&attributes.KeyAlgorithm, certAttrs.KeyAlgorithm)
	setString(&attributes.SignatureAlgorithm, certAttrs.SignatureAlgorithm)
	setString(&attributes.NotBefore, certAttrs.NotBefore)
	setString(&attributes.NotAfter, certAttrs.NotAfter)
	setStringSlice(&attributes.KeyUsages, certAttrs.KeyUsages)
	setStringSlice(&attributes.ExtendedKeyUsages, certAttrs.ExtendedKeyUsages)

	removeRoots := true
	if certificate.FileConfig.Chain.OmitRoot != nil && !*certificate.FileConfig.Chain.OmitRoot {
		removeRoots = false
	}

	attributes.RemoveRootsFromChain = removeRoots
	hasAny = true

	if len(certAttrs.AltNames) > 0 {
		altNames := make([]api.AltName, len(certAttrs.AltNames))
		for i, altName := range certAttrs.AltNames {
			altNames[i] = api.AltName{Type: "dns_name", Value: altName}
		}
		attributes.AltNames = altNames
		hasAny = true
	}

	if !hasAny {
		return nil
	}
	return attributes
}

func (tm *AgentManager) createAuthenticatedClient() (*resty.Client, error) {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	token := tm.getTokenUnsafe()
	if token == "" {
		return nil, fmt.Errorf("no access token available")
	}
	httpClient.SetAuthToken(token)
	return httpClient, nil
}

func (tm *AgentManager) IssueCertificate(certificateId int, certificate *AgentCertificateConfig) error {
	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	log.Info().Str("Certificate", displayName).Msg("issuing certificate")

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	state := tm.certificateStates[certificateId]

	request := api.IssueCertificateRequest{
		ProfileID: certificate.ProfileID,
	}

	if certificate.CSR != "" {
		request.CSR = certificate.CSR
	}

	if attributes := buildCertificateAttributes(certificate); attributes != nil {
		request.Attributes = attributes
	}

	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		return err
	}

	response, err := api.CallIssueCertificate(httpClient, request)
	if err != nil {
		state.Status = "failed"
		state.LastError = err.Error()
		state.RetryCount++
		state.LastRetry = time.Now()
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Error().Str("Certificate", displayName).Msgf("failed to issue certificate: %v", err)
		return fmt.Errorf("failed to issue certificate: %v", err)
	}

	setCommonName := func() {
		if certificate.Attributes != nil {
			state.CommonName = certificate.Attributes.CommonName
		}

		if state.CommonName == "" && request.Attributes != nil {
			state.CommonName = request.Attributes.CommonName
		}
	}

	if response.Certificate != nil {
		state.CertificateID = response.Certificate.CertificateID
		state.SerialNumber = response.Certificate.SerialNumber
		setCommonName()
		state.IssuedAt = time.Now()
		state.Status = "active"
		state.LastError = ""
		state.RetryCount = 0
	} else {
		state.CertificateRequestID = response.CertificateRequestID
		setCommonName()
		state.Status = "pending_issuance"
		state.LastError = ""
		state.RetryCount = 0

		go tm.PollCertificateRequest(certificateId, certificate)
		return nil
	}

	if ttlDuration, err := parseDurationWithDays(tm.getCertificateTTL(certificate)); err == nil {
		state.ExpiresAt = state.IssuedAt.Add(ttlDuration)
	} else {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Warn().Str("Certificate", displayName).Msg("unable to parse TTL")
		state.ExpiresAt = state.IssuedAt.Add(24 * time.Hour)
	}

	if renewBeforeDuration, err := parseDurationWithDays(certificate.Lifecycle.RenewBeforeExpiry); err == nil {
		state.NextRenewalCheck = state.ExpiresAt.Add(-renewBeforeDuration)
	} else {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Warn().Str("Certificate", displayName).Msg("unable to parse lifecycle.renew-before-expiry")
		state.NextRenewalCheck = state.ExpiresAt.Add(-24 * time.Hour)
	}

	err = tm.WriteCertificateFiles(certificate, response)
	if err != nil {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Error().Str("Certificate", displayName).Msgf("failed to write certificate files: %v", err)
		state.Status = "failed"
		state.LastError = fmt.Sprintf("failed to write files: %v", err)
		return err
	}

	log.Info().Str("Certificate", displayName).Str("serial", response.Certificate.SerialNumber).Msg("certificate issued successfully")

	if certificate.PostHooks.OnIssuance.Command != "" {
		tm.ExecutePostHook(certificate.PostHooks.OnIssuance.Command, certificate.PostHooks.OnIssuance.Timeout, "issuance", certificateId, certificate)
	}

	return nil
}

func (tm *AgentManager) PollCertificateRequest(certificateId int, certificate *AgentCertificateConfig) {
	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	pollingInterval := EXTERNAL_CA_INITIAL_POLLING_INTERVAL

	for {
		if err := tm.checkCertificateRequestStatus(certificateId, certificate); err != nil {
			log.Error().Str("Certificate", displayName).Msgf("failed to check certificate request status: %v", err)
		}

		var status string
		func() {
			tm.mutex.Lock()
			defer tm.mutex.Unlock()
			state := tm.certificateStates[certificateId]
			status = state.Status
		}()

		if status == "active" {
			log.Info().Str("Certificate", displayName).Msg("certificate issued successfully by external CA")
			return
		} else if status == "failed" {
			log.Error().Str("Certificate", displayName).Msg("certificate issuance failed")
			return
		}

		log.Info().Str("Certificate", displayName).Msgf("waiting %s before next polling attempt", pollingInterval)
		time.Sleep(pollingInterval)

		pollingInterval *= 2
		if pollingInterval > EXTERNAL_CA_MAX_POLLING_INTERVAL {
			pollingInterval = EXTERNAL_CA_MAX_POLLING_INTERVAL
		}
	}
}

func (tm *AgentManager) checkCertificateRequestStatus(certificateId int, certificate *AgentCertificateConfig) error {
	var requestID string
	func() {
		tm.mutex.Lock()
		defer tm.mutex.Unlock()

		state := tm.certificateStates[certificateId]
		if state.CertificateRequestID == "" {
			return
		}
		requestID = state.CertificateRequestID
	}()

	if requestID == "" {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		return fmt.Errorf("no certificate request ID found for certificate %s", displayName)
	}

	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		return err
	}

	response, err := api.CallGetCertificateRequest(httpClient, requestID)
	if err != nil {
		return fmt.Errorf("failed to get certificate request status: %v", err)
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	state := tm.certificateStates[certificateId]

	switch response.Status {
	case "issued":
		if response.Certificate == nil || response.SerialNumber == nil || response.CertificateID == nil {
			return nil
		}

		state.CertificateID = *response.CertificateID
		state.SerialNumber = *response.SerialNumber
		state.IssuedAt = time.Now()
		state.Status = "active"
		state.LastError = ""
		state.RetryCount = 0

		if ttlDuration, err := parseDurationWithDays(tm.getCertificateTTL(certificate)); err == nil {
			state.ExpiresAt = state.IssuedAt.Add(ttlDuration)
		} else {
			state.ExpiresAt = state.IssuedAt.Add(24 * time.Hour)
		}

		if renewBeforeDuration, err := parseDurationWithDays(certificate.Lifecycle.RenewBeforeExpiry); err == nil {
			state.NextRenewalCheck = state.ExpiresAt.Add(-renewBeforeDuration)
		} else {
			state.NextRenewalCheck = state.ExpiresAt.Add(-24 * time.Hour)
		}

		certData := api.CertificateData{
			Certificate:   *response.Certificate,
			CertificateID: state.CertificateRequestID,
			SerialNumber:  *response.SerialNumber,
		}
		if response.IssuingCaCertificate != nil {
			certData.IssuingCaCertificate = *response.IssuingCaCertificate
		}
		if response.CertificateChain != nil {
			certData.CertificateChain = *response.CertificateChain
		}
		if response.PrivateKey != nil {
			certData.PrivateKey = *response.PrivateKey
		}

		certResponse := &api.CertificateResponse{
			Certificate: &certData,
		}

		if err := tm.WriteCertificateFiles(certificate, certResponse); err != nil {
			displayName := tm.getCertificateDisplayName(certificateId, certificate)
			log.Error().Str("Certificate", displayName).Msgf("failed to write certificate files: %v", err)
			state.Status = "failed"
			state.LastError = fmt.Sprintf("failed to write files: %v", err)
			return err
		}

		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Info().Str("Certificate", displayName).Str("serial", *response.SerialNumber).Msg("certificate issued successfully")

		if certificate.PostHooks.OnIssuance.Command != "" {
			tm.ExecutePostHook(certificate.PostHooks.OnIssuance.Command, certificate.PostHooks.OnIssuance.Timeout, "issuance", certificateId, certificate)
		}

	case "failed":
		errorMsg := "unknown error"
		if response.ErrorMessage != nil {
			errorMsg = *response.ErrorMessage
		}
		tm.handleFailedCertificateRequest(certificateId, errorMsg)

	case "pending":
		// Still waiting, no action needed

	default:
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Warn().Str("Certificate", displayName).Msg("unknown certificate request status")
	}

	return nil
}

func (tm *AgentManager) handleFailedCertificateRequest(certificateId int, errorMsg string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	state := tm.certificateStates[certificateId]
	state.Status = "failed"
	state.LastError = errorMsg
	state.RetryCount++
	state.LastRetry = time.Now()

	var certificate *AgentCertificateConfig
	for _, cert := range tm.certificates {
		if cert.ID == certificateId {
			certificate = &cert.Certificate
			break
		}
	}

	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	log.Error().Str("Certificate", displayName).Msgf("certificate request failed: %s", errorMsg)

	if certificate != nil && certificate.PostHooks.OnFailure.Command != "" {
		go tm.ExecutePostHook(certificate.PostHooks.OnFailure.Command, certificate.PostHooks.OnFailure.Timeout, "failure", certificateId, certificate)
	}
}

func (tm *AgentManager) WriteCertificateFiles(certificate *AgentCertificateConfig, response *api.CertificateResponse) error {
	getFilePermission := func(permission string) os.FileMode {
		if permission != "" {
			if perms, err := strconv.ParseInt(permission, 8, 32); err == nil {
				return os.FileMode(perms)
			}
		}
		return os.FileMode(0600)
	}

	privateKeyPath := certificate.FileConfig.PrivateKey.Path
	privateKeyPerms := getFilePermission(certificate.FileConfig.PrivateKey.Permission)

	certificatePath := certificate.FileConfig.Certificate.Path
	certificatePerms := getFilePermission(certificate.FileConfig.Certificate.Permission)

	chainPath := certificate.FileConfig.Chain.Path
	chainPerms := getFilePermission(certificate.FileConfig.Chain.Permission)

	if certificatePath == "" {
		return fmt.Errorf("certificate.path is required in file-output configuration")
	}

	if response.Certificate.PrivateKey != "" {
		if privateKeyPath == "" {
			return fmt.Errorf("private-key.path is required when private key is present")
		}
		if err := os.MkdirAll(path.Dir(privateKeyPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for private key %s: %v", privateKeyPath, err)
		}
		if err := ioutil.WriteFile(privateKeyPath, []byte(response.Certificate.PrivateKey), privateKeyPerms); err != nil {
			return fmt.Errorf("failed to write private key to %s: %v", privateKeyPath, err)
		}
	}

	if err := os.MkdirAll(path.Dir(certificatePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for certificate %s: %v", certificatePath, err)
	}
	if err := ioutil.WriteFile(certificatePath, []byte(response.Certificate.Certificate), certificatePerms); err != nil {
		return fmt.Errorf("failed to write certificate to %s: %v", certificatePath, err)
	}

	if response.Certificate.CertificateChain != "" && chainPath != "" {
		if err := os.MkdirAll(path.Dir(chainPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for certificate chain %s: %v", chainPath, err)
		}
		if err := ioutil.WriteFile(chainPath, []byte(response.Certificate.CertificateChain), chainPerms); err != nil {
			return fmt.Errorf("failed to write certificate chain to %s: %v", chainPath, err)
		}
	}

	return nil
}

func (tm *AgentManager) ExecutePostHook(command string, timeoutSecs int64, hookType string, certificateId int, certificate *AgentCertificateConfig) {
	if command == "" {
		return
	}

	timeout := time.Duration(timeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	log.Info().Str("Certificate", displayName).Msg("executing post-hook")

	go func() {
		err := ExecuteCommandWithTimeout(command, int64(timeout.Seconds()))
		if err != nil {
			log.Error().Str("Certificate", displayName).Msgf("post-hook execution failed: %v", err)
		} else {
			log.Info().Str("Certificate", displayName).Msg("post-hook execution successful")
		}
	}()
}

func (tm *AgentManager) MonitorCertificates(ctx context.Context) {
	if len(tm.certificates) == 0 {
		return
	}

	log.Info().Msg("starting certificate monitoring")

	var monitoringInterval time.Duration = DEFAULT_MONITORING_INTERVAL
	for _, cert := range tm.certificates {
		if interval, err := parseDurationWithDays(cert.Certificate.Lifecycle.StatusCheckInterval); err == nil {
			if monitoringInterval == 0 || interval < monitoringInterval {
				monitoringInterval = interval
			}
		}
	}

	ticker := time.NewTicker(monitoringInterval)
	defer ticker.Stop()

	for {
		var token string
		func() {
			tm.mutex.Lock()
			defer tm.mutex.Unlock()
			token = tm.getTokenUnsafe()
		}()

		if token != "" {
			break
		}

		time.Sleep(1 * time.Second)
	}

	for _, cert := range tm.certificates {
		tm.certificateFirstIssueOnce[cert.ID].Do(func() {
			if err := tm.IssueCertificate(cert.ID, &cert.Certificate); err != nil {
				displayName := tm.getCertificateDisplayName(cert.ID, &cert.Certificate)
				log.Error().Str("Certificate", displayName).Msgf("initial certificate issuance failed: %v", err)
			}
		})
	}

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("stopping certificate monitoring")
			return
		case <-ticker.C:
			tm.CheckCertificateRenewals()
		}
	}
}

func (tm *AgentManager) CheckCertificateRenewals() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	now := time.Now()

	for _, cert := range tm.certificates {
		state := tm.certificateStates[cert.ID]

		if cert.Certificate.CSR != "" || cert.Certificate.CSRPath != "" {
			continue
		}

		if state.Status != "active" || now.Before(state.NextRenewalCheck) {
			continue
		}

		displayName := tm.getCertificateDisplayName(cert.ID, &cert.Certificate)
		log.Info().Str("Certificate", displayName).Msg("checking certificate for renewal")

		if state.CertificateID != "" {
			tm.mutex.Unlock()
			if err := tm.CheckCertificateStatus(cert.ID, state.CertificateID); err != nil {
				log.Error().Str("Certificate", displayName).Msgf("failed to check status: %v", err)
			}
			tm.mutex.Lock()
		}
		if tm.ShouldRenewCertificate(cert.ID) {
			log.Info().Str("Certificate", displayName).Msg("renewing certificate")
			if err := tm.RenewCertificate(cert.ID, &cert.Certificate); err != nil {
				log.Error().Str("Certificate", displayName).Msgf("failed to renew certificate: %v", err)
				state.Status = "failed"
				state.LastError = err.Error()
				state.RetryCount++
				state.LastRetry = now
			}
		}
	}
}

func (tm *AgentManager) CheckCertificateStatus(certificateId int, infisicalCertId string) error {
	httpClient, err := util.GetRestyClientWithCustomHeaders()
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %v", err)
	}
	httpClient.SetAuthToken(tm.getTokenUnsafe())

	response, err := api.CallRetrieveCertificate(httpClient, infisicalCertId)
	if err != nil {
		return fmt.Errorf("failed to retrieve certificate status: %v", err)
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	state := tm.certificateStates[certificateId]
	previousStatus := state.Status

	state.Status = response.Certificate.Status
	state.ExpiresAt = response.Certificate.NotAfter

	if previousStatus != state.Status {
		var certificate *AgentCertificateConfig
		for _, cert := range tm.certificates {
			if cert.ID == certificateId {
				certificate = &cert.Certificate
				break
			}
		}
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Info().Str("Certificate", displayName).Msg("certificate status changed")

		if state.Status == "revoked" {
			log.Error().Str("Certificate", displayName).Msg("certificate has been revoked - stopping renewal attempts")
			state.LastError = "certificate has been revoked"

			for _, cert := range tm.certificates {
				if cert.ID == certificateId {
					if cert.Certificate.PostHooks.OnFailure.Command != "" {
						displayName := tm.getCertificateDisplayName(certificateId, &cert.Certificate)
						log.Info().Str("Certificate", displayName).Msg("executing revocation post-hook")
						go tm.ExecutePostHook(cert.Certificate.PostHooks.OnFailure.Command, cert.Certificate.PostHooks.OnFailure.Timeout, "revocation", certificateId, &cert.Certificate)
					}
					break
				}
			}
		} else if state.Status == "expired" {
			log.Error().Str("Certificate", displayName).Msg("certificate has expired - stopping renewal attempts")
			state.LastError = "certificate has expired"

			for _, cert := range tm.certificates {
				if cert.ID == certificateId {
					if cert.Certificate.PostHooks.OnFailure.Command != "" {
						displayName := tm.getCertificateDisplayName(certificateId, &cert.Certificate)
						log.Info().Str("Certificate", displayName).Msg("executing expiration post-hook")
						go tm.ExecutePostHook(cert.Certificate.PostHooks.OnFailure.Command, cert.Certificate.PostHooks.OnFailure.Timeout, "expiration", certificateId, &cert.Certificate)
					}
					break
				}
			}
		}
	}

	return nil
}

func (tm *AgentManager) ShouldRenewCertificate(certificateId int) bool {
	state := tm.certificateStates[certificateId]

	var cert *AgentCertificateConfig
	for _, c := range tm.certificates {
		if c.ID == certificateId {
			cert = &c.Certificate
			break
		}
	}

	if state.Status != "active" {
		return false
	}

	if state.CertificateID == "" {
		return false
	}

	if cert == nil {
		return false
	}

	now := time.Now()

	if now.After(state.ExpiresAt) {
		return true
	}

	if renewBefore, err := parseDurationWithDays(cert.Lifecycle.RenewBeforeExpiry); err == nil {
		renewTime := state.ExpiresAt.Add(-renewBefore)
		return now.After(renewTime)
	}

	return false
}

func (tm *AgentManager) RenewCertificate(certificateId int, certificate *AgentCertificateConfig) error {
	state := tm.certificateStates[certificateId]

	if state.CertificateID == "" {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		return fmt.Errorf("no certificate ID found for certificate %s", displayName)
	}

	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		return err
	}

	removeRoots := true
	if certificate.FileConfig.Chain.OmitRoot != nil && !*certificate.FileConfig.Chain.OmitRoot {
		removeRoots = false
	}

	request := api.RenewCertificateRequest{
		RemoveRootsFromChain: removeRoots,
	}
	response, err := api.CallRenewCertificate(httpClient, state.CertificateID, request)
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %v", err)
	}

	if response.CertificateRequestID != "" {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Info().Str("Certificate", displayName).Msg("certificate submitted for renewal to external CA")

		state.CertificateRequestID = response.CertificateRequestID
		state.Status = "renewing"
		state.LastError = ""
		state.RetryCount = 0

		go tm.PollCertificateRequestForRenewal(certificateId, certificate, response.CertificateRequestID)

		return nil
	}

	return tm.handleImmediateRenewalResponse(certificateId, certificate, response)
}

func (tm *AgentManager) handleImmediateRenewalResponse(certificateId int, certificate *AgentCertificateConfig, response *api.RenewCertificateResponse) error {
	state := tm.certificateStates[certificateId]

	state.CertificateID = response.CertificateID
	state.SerialNumber = response.SerialNumber
	state.IssuedAt = time.Now()
	state.Status = "active"
	state.LastError = ""
	state.RetryCount = 0

	if ttlDuration, err := parseDurationWithDays(tm.getCertificateTTL(certificate)); err == nil {
		state.ExpiresAt = state.IssuedAt.Add(ttlDuration)
	}

	if renewBeforeDuration, err := parseDurationWithDays(certificate.Lifecycle.RenewBeforeExpiry); err == nil {
		state.NextRenewalCheck = state.ExpiresAt.Add(-renewBeforeDuration)
	}

	certResponse := &api.CertificateResponse{
		Certificate: &api.CertificateData{
			Certificate:          response.Certificate,
			IssuingCaCertificate: response.IssuingCaCertificate,
			CertificateChain:     response.CertificateChain,
			PrivateKey:           response.PrivateKey,
			SerialNumber:         response.SerialNumber,
			CertificateID:        response.CertificateID,
		},
	}

	err := tm.WriteCertificateFiles(certificate, certResponse)
	if err != nil {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Error().Str("Certificate", displayName).Msgf("failed to write renewed certificate files: %v", err)
		state.Status = "failed"
		state.LastError = fmt.Sprintf("failed to write files: %v", err)
		return err
	}

	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	log.Info().Str("Certificate", displayName).Str("serial", response.SerialNumber).Msg("certificate renewed successfully")

	if certificate.PostHooks.OnRenewal.Command != "" {
		tm.ExecutePostHook(certificate.PostHooks.OnRenewal.Command, certificate.PostHooks.OnRenewal.Timeout, "renewal", certificateId, certificate)
	}

	return nil
}

func (tm *AgentManager) PollCertificateRequestForRenewal(certificateId int, certificate *AgentCertificateConfig, requestID string) {
	pollingInterval := EXTERNAL_CA_INITIAL_POLLING_INTERVAL
	displayName := tm.getCertificateDisplayName(certificateId, certificate)

	for {
		status, certResponse, err := tm.checkCertificateRequestStatusByID(requestID)
		if err != nil {
			log.Error().Str("Certificate", displayName).Msgf("failed to check renewal status: %v", err)

			func() {
				tm.mutex.Lock()
				defer tm.mutex.Unlock()
				state := tm.certificateStates[certificateId]
				state.LastError = fmt.Sprintf("polling error: %v", err)
				state.RetryCount++
			}()

			log.Info().Str("Certificate", displayName).Msgf("waiting %s before next renewal polling attempt", pollingInterval)
			time.Sleep(pollingInterval)

			pollingInterval *= 2
			if pollingInterval > EXTERNAL_CA_MAX_POLLING_INTERVAL {
				pollingInterval = EXTERNAL_CA_MAX_POLLING_INTERVAL
			}
			continue
		}

		var shouldReturn bool
		var shouldContinue bool

		func() {
			tm.mutex.Lock()
			defer tm.mutex.Unlock()

			state := tm.certificateStates[certificateId]

			switch status {
			case "issued":
				if certResponse == nil {
					shouldContinue = true
					return
				}

				if certResponse.Certificate == nil {
					log.Error().Str("Certificate", displayName).Msg("certificate renewal failed: no certificate data received")
					tm.handleFailedCertificateRenewal(certificateId, certificate, "no certificate data in issued response")
					shouldReturn = true
					return
				}

				log.Info().Str("Certificate", displayName).Msg("certificate renewed successfully")

				state.CertificateID = certResponse.Certificate.CertificateID
				state.SerialNumber = certResponse.Certificate.SerialNumber
				state.IssuedAt = time.Now()
				state.Status = "active"
				state.LastError = ""
				state.RetryCount = 0
				state.CertificateRequestID = requestID

				if ttlDuration, err := parseDurationWithDays(tm.getCertificateTTL(certificate)); err == nil {
					state.ExpiresAt = state.IssuedAt.Add(ttlDuration)
				}

				if renewBeforeDuration, err := parseDurationWithDays(certificate.Lifecycle.RenewBeforeExpiry); err == nil {
					state.NextRenewalCheck = state.ExpiresAt.Add(-renewBeforeDuration)
				}

			case "failed":
				log.Error().Str("Certificate", displayName).Msg("certificate renewal failed")
				tm.handleFailedCertificateRenewal(certificateId, certificate, "external CA renewal failed")
				shouldReturn = true
				return

			case "pending":
				// Continue polling

			default:
				log.Warn().Str("Certificate", displayName).Msg("unknown renewal status")
			}
		}()

		if shouldReturn {
			return
		}

		if shouldContinue {
			time.Sleep(pollingInterval)
			continue
		}

		if status == "issued" && certResponse != nil && certResponse.Certificate != nil {
			if err := tm.WriteCertificateFiles(certificate, certResponse); err != nil {
				log.Error().Str("Certificate", displayName).Msgf("failed to write renewed certificate files: %v", err)

				func() {
					tm.mutex.Lock()
					defer tm.mutex.Unlock()
					state := tm.certificateStates[certificateId]
					state.Status = "failed"
					state.LastError = fmt.Sprintf("failed to write files: %v", err)
				}()
				return
			}

			log.Info().Str("Certificate", displayName).Str("serial", certResponse.Certificate.SerialNumber).Msg("successfully renewed certificate")

			if certificate.PostHooks.OnRenewal.Command != "" {
				tm.ExecutePostHook(certificate.PostHooks.OnRenewal.Command, certificate.PostHooks.OnRenewal.Timeout, "renewal", certificateId, certificate)
			}
			return
		}

		log.Info().Str("Certificate", displayName).Msgf("waiting %s before next renewal polling attempt", pollingInterval)
		time.Sleep(pollingInterval)

		pollingInterval *= 2
		if pollingInterval > EXTERNAL_CA_MAX_POLLING_INTERVAL {
			pollingInterval = EXTERNAL_CA_MAX_POLLING_INTERVAL
		}
	}
}

func (tm *AgentManager) handleFailedCertificateRenewal(certificateId int, certificate *AgentCertificateConfig, reason string) {
	state := tm.certificateStates[certificateId]
	state.Status = "failed"
	state.LastError = fmt.Sprintf("renewal failed: %s", reason)
	state.RetryCount++
	state.CertificateRequestID = ""

	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	log.Error().Str("Certificate", displayName).Msgf("renewal failed: %s", reason)

	if certificate.PostHooks.OnFailure.Command != "" {
		tm.ExecutePostHook(certificate.PostHooks.OnFailure.Command, certificate.PostHooks.OnFailure.Timeout, "failure", certificateId, certificate)
	}

	if state.RetryCount < certificate.Lifecycle.MaxFailureRetries {
		state.LastRetry = time.Now()
		log.Info().Str("Certificate", displayName).Msg("scheduling retry for certificate renewal")
	} else {
		log.Error().Str("Certificate", displayName).Msg("max retries exceeded for certificate renewal")
	}
}

func (tm *AgentManager) handleImmediateRenewalResponseFromIssuance(certificateId int, certificate *AgentCertificateConfig, response *api.CertificateResponse) error {
	state := tm.certificateStates[certificateId]

	state.CertificateID = response.Certificate.CertificateID
	state.SerialNumber = response.Certificate.SerialNumber
	state.IssuedAt = time.Now()
	state.Status = "active"
	state.LastError = ""
	state.RetryCount = 0

	if ttlDuration, err := parseDurationWithDays(tm.getCertificateTTL(certificate)); err == nil {
		state.ExpiresAt = state.IssuedAt.Add(ttlDuration)
	}

	if renewBeforeDuration, err := parseDurationWithDays(certificate.Lifecycle.RenewBeforeExpiry); err == nil {
		state.NextRenewalCheck = state.ExpiresAt.Add(-renewBeforeDuration)
	}

	err := tm.WriteCertificateFiles(certificate, response)
	if err != nil {
		displayName := tm.getCertificateDisplayName(certificateId, certificate)
		log.Error().Str("Certificate", displayName).Msgf("failed to write renewed certificate files: %v", err)
		state.Status = "failed"
		state.LastError = fmt.Sprintf("failed to write files: %v", err)
		return err
	}

	displayName := tm.getCertificateDisplayName(certificateId, certificate)
	log.Info().Str("Certificate", displayName).Str("serial", response.Certificate.SerialNumber).Msg("successfully renewed certificate")

	if certificate.PostHooks.OnRenewal.Command != "" {
		tm.ExecutePostHook(certificate.PostHooks.OnRenewal.Command, certificate.PostHooks.OnRenewal.Timeout, "renewal", certificateId, certificate)
	}

	return nil
}

func (tm *AgentManager) checkCertificateRequestStatusByID(requestID string) (string, *api.CertificateResponse, error) {
	httpClient, err := tm.createAuthenticatedClient()
	if err != nil {
		return "", nil, err
	}

	response, err := api.CallGetCertificateRequest(httpClient, requestID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get certificate request status: %v", err)
	}

	if response.Status == "issued" {
		if response.Certificate == nil || response.SerialNumber == nil || response.CertificateID == nil {
			return response.Status, nil, nil
		}

		certData := &api.CertificateData{
			Certificate:   *response.Certificate,
			SerialNumber:  *response.SerialNumber,
			CertificateID: *response.CertificateID,
		}

		if response.IssuingCaCertificate != nil {
			certData.IssuingCaCertificate = *response.IssuingCaCertificate
		}
		if response.CertificateChain != nil {
			certData.CertificateChain = *response.CertificateChain
		}
		if response.PrivateKey != nil {
			certData.PrivateKey = *response.PrivateKey
		}

		return response.Status, &api.CertificateResponse{Certificate: certData}, nil
	}

	return response.Status, nil, nil
}

// runCmd represents the run command
var agentCmd = &cobra.Command{
	Example: `
	infisical agent
	`,
	Use:                   "agent",
	Short:                 "Used to launch a client daemon that streamlines authentication and secret retrieval processes in various environments",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {

		log.Info().Msg("starting Infisical agent...")

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			util.HandleError(err, "Unable to parse flag config")
		}

		var agentConfigInBytes []byte

		agentConfigInBase64 := os.Getenv("INFISICAL_AGENT_CONFIG_BASE64")

		if agentConfigInBase64 == "" {
			data, err := ioutil.ReadFile(configPath)
			if err != nil {
				if !FileExists(configPath) {
					log.Error().Msgf("Unable to locate %s. The provided agent config file path is either missing or incorrect", configPath)
					return
				}
			} // pgrep -f "dev-agent"
			agentConfigInBytes = data
		}

		if agentConfigInBase64 != "" {
			decodedAgentConfig, err := base64.StdEncoding.DecodeString(agentConfigInBase64)
			if err != nil {
				log.Error().Msgf("Unable to decode base64 config file because %v", err)
				return
			}

			agentConfigInBytes = decodedAgentConfig
		}

		if !FileExists(configPath) && agentConfigInBase64 == "" {
			log.Error().Msgf("No agent config file provided at %v. Please provide a agent config file", configPath)
			return
		}

		agentConfig, err := ParseAgentConfig(agentConfigInBytes)
		if err != nil {
			log.Error().Msgf("Unable to parse %s because %v. Please ensure that it follows the Infisical Agent config structure", configPath, err)
			return
		}

		err = processCertificateCSRPaths(&agentConfig.Certificates)
		if err != nil {
			log.Error().Msgf("Failed to load CSR files: %v", err)
			return
		}

		err = validateCertificateLifecycleConfig(&agentConfig.Certificates)
		if err != nil {
			log.Error().Msgf("Certificate lifecycle configuration validation failed: %v", err)
			return
		}

		authMethodValid, authStrategy := util.IsAuthMethodValid(agentConfig.Auth.Type, false)

		if !authMethodValid {
			util.PrintErrorMessageAndExit(fmt.Sprintf("The auth method '%s' is not supported.", agentConfig.Auth.Type))
		}

		ctx, cancel := context.WithCancel(context.Background())

		tokenRefreshNotifier := make(chan bool)
		monitoringChan := make(chan bool, len(agentConfig.Templates))
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		filePaths := agentConfig.Sinks

		configBytes, err := yaml.Marshal(agentConfig.Auth.Config)
		if err != nil {
			log.Error().Msgf("unable to marshal auth config because %v", err)
			cancel()
			return
		}

		var certificates []AgentCertificateConfig
		if agentConfig.Version != "" {
			certificates = agentConfig.Certificates
		}

		tm := NewAgentManager(NewAgentMangerOptions{
			FileDeposits:                   filePaths,
			Templates:                      agentConfig.Templates,
			Certificates:                   certificates,
			AuthConfigBytes:                configBytes,
			NewAccessTokenNotificationChan: tokenRefreshNotifier,
			ExitAfterAuth:                  agentConfig.Infisical.ExitAfterAuth,
			AuthStrategy:                   authStrategy,
			RevokeCredentialsOnShutdown:    agentConfig.Infisical.RevokeCredentialsOnShutdown,
			RetryConfig:                    agentConfig.Infisical.RetryConfig,
		})

		tm.cacheManager, err = NewCacheManager(ctx, &agentConfig.Cache)
		if err != nil {
			log.Error().Msgf("unable to setup cache manager: %v", err)
			cancel()
			return
		}
		tm.dynamicSecretLeases = NewDynamicSecretLeaseManager(tm.cacheManager, tm.SdkRetryConfig())

		// start a http server that returns a json object of the whole cache
		if util.IsDevelopmentMode() && tm.cacheManager != nil && tm.cacheManager.IsEnabled {

			go func() {
				http.HandleFunc("/cache", func(w http.ResponseWriter, r *http.Request) {

					all, err := tm.cacheManager.cacheStorage.GetAll()
					if err != nil {
						log.Error().Msgf("unable to get all cache: %v", err)
						json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
						return
					}

					json.NewEncoder(w).Encode(all)

				})
				log.Info().Msg("starting cache http server on port 9000")
				http.ListenAndServe(":9000", nil)
			}()
		}

		go tm.ManageTokenLifecycle()

		if len(agentConfig.Certificates) > 0 {
			go func() {
				for {
					if tm.getTokenUnsafe() != "" {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}

				httpClient, err := tm.createAuthenticatedClient()
				if err != nil {
					log.Error().Msgf("failed to create authenticated client for name resolution: %v", err)
					return
				}

				err = resolveCertificateNameReferences(&agentConfig.Certificates, httpClient)
				if err != nil {
					log.Error().Msgf("failed to resolve certificate name references: %v", err)
					return
				}

				for i := range tm.certificates {
					for j := range agentConfig.Certificates {
						if tm.certificates[i].ID == j+1 {
							tm.certificates[i].Certificate = agentConfig.Certificates[j]
							break
						}
					}
				}
			}()
		}

		var monitoredTemplatesFinished atomic.Int32

		// when all templates have finished rendering once, we delete the unused leases from the cache.
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-monitoringChan:
					monitoredTemplatesFinished.Add(1)
					if monitoredTemplatesFinished.Load() == int32(len(tm.templates)) {
						if err := tm.dynamicSecretLeases.DeleteUnusedLeasesFromCache(); err != nil {
							log.Error().Msgf("[template monitor] failed to delete unused leases from cache: %v", err)
						}

						if tm.exitAfterAuth {
							log.Info().Msg("agent is exiting after all templates have finished rendering once...")
							os.Exit(0)
						}
					}
				}
			}
		}()

		for _, template := range tm.templates {
			log.Info().Msgf("template engine started for template %v...", template.ID)
			go tm.MonitorSecretChanges(ctx, template.Template, template.ID, sigChan, monitoringChan)
		}

		if len(tm.certificates) > 0 {
			log.Info().Msg("certificate management engine starting...")
			go tm.MonitorCertificates(ctx)
		}

		for {
			select {
			case <-tokenRefreshNotifier:
				go tm.WriteTokenToFiles()
			case <-sigChan:
				tm.isShuttingDown = true
				tm.cancelContext()
				log.Info().Msg("agent is gracefully shutting down...")
				cancel()

				exitCode := 0

				if !tm.exitAfterAuth && tm.revokeCredentialsOnShutdown {

					done := make(chan error, 1)

					go func() {
						done <- tm.RevokeCredentials()
					}()

					select {
					case err := <-done:
						if err != nil {
							log.Error().Msgf("unable to revoke credentials [err=%v]", err)
							exitCode = 1
						}
					// 5 minute timeout to prevent any hanging edge cases
					case <-time.After(5 * time.Minute):
						log.Warn().Msg("credential revocation timed out after 5 minutes, forcing exit")
						exitCode = 1
					}
				}

				os.Exit(exitCode)
			}
		}

	},
}

func validateCertificateOnlyMode(config *Config) error {
	if config.Version != "v1" {
		return fmt.Errorf("certificate management requires version: v1")
	}

	if len(config.Certificates) == 0 {
		return fmt.Errorf("certificate management requires at least one certificate to be configured")
	}

	if len(config.Templates) > 0 {
		return fmt.Errorf("certificate-only mode does not support templates. Use regular 'infisical agent' for secrets management")
	}

	return nil
}

var certManagerCmd = &cobra.Command{
	Use:   "cert-manager",
	Short: "Certificate management commands",
	Long:  "Commands for managing certificates through the Infisical agent",
}

var certManagerAgentCmd = &cobra.Command{
	Example: `
	infisical cert-manager agent --config certificate-agent-config.yaml
	`,
	Use:                   "agent",
	Short:                 "Launch certificate management agent",
	Long:                  "Used to launch a client daemon specifically for certificate management and lifecycle automation",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {

		log.Info().Msg("starting Infisical certificate management agent...")

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			util.HandleError(err, "Unable to parse flag config")
		}

		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			util.HandleError(err, "Unable to parse flag verbose")
		}

		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}

		var agentConfigInBytes []byte

		agentConfigInBase64 := os.Getenv("INFISICAL_AGENT_CONFIG_BASE64")

		if agentConfigInBase64 == "" {
			data, err := ioutil.ReadFile(configPath)
			if err != nil {
				if !FileExists(configPath) {
					log.Error().Msgf("Unable to locate %s. The provided agent config file path is either missing or incorrect", configPath)
					return
				}
			}
			agentConfigInBytes = data
		}

		if agentConfigInBase64 != "" {
			decodedAgentConfig, err := base64.StdEncoding.DecodeString(agentConfigInBase64)
			if err != nil {
				log.Error().Msgf("Unable to decode base64 config file because %v", err)
				return
			}

			agentConfigInBytes = decodedAgentConfig
		}

		if !FileExists(configPath) && agentConfigInBase64 == "" {
			log.Error().Msgf("No agent config file provided at %v. Please provide a agent config file", configPath)
			return
		}

		agentConfig, err := ParseAgentConfigForCertManager(agentConfigInBytes)
		if err != nil {
			log.Error().Msgf("Unable to parse %s because %v. Please ensure that it follows the Infisical Agent config structure", configPath, err)
			return
		}

		if err := validateCertificateOnlyMode(agentConfig); err != nil {
			log.Error().Msgf("Certificate-only mode validation failed: %v", err)
			return
		}

		err = processCertificateCSRPaths(&agentConfig.Certificates)
		if err != nil {
			log.Error().Msgf("Failed to load CSR files: %v", err)
			return
		}

		err = validateCertificateLifecycleConfig(&agentConfig.Certificates)
		if err != nil {
			log.Error().Msgf("Certificate lifecycle configuration validation failed: %v", err)
			return
		}

		authMethodValid, authStrategy := util.IsAuthMethodValid(agentConfig.Auth.Type, false)

		if !authMethodValid {
			util.PrintErrorMessageAndExit(fmt.Sprintf("The auth method '%s' is not supported.", agentConfig.Auth.Type))
		}

		ctx, cancel := context.WithCancel(context.Background())

		tokenRefreshNotifier := make(chan bool)
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		filePaths := agentConfig.Sinks

		configBytes, err := yaml.Marshal(agentConfig.Auth.Config)
		if err != nil {
			log.Error().Msgf("unable to marshal auth config because %v", err)
			cancel()
			return
		}

		tm := NewAgentManager(NewAgentMangerOptions{
			FileDeposits:                   filePaths,
			Templates:                      []Template{}, // No templates in cert-only mode
			Certificates:                   agentConfig.Certificates,
			AuthConfigBytes:                configBytes,
			NewAccessTokenNotificationChan: tokenRefreshNotifier,
			ExitAfterAuth:                  agentConfig.Infisical.ExitAfterAuth,
			AuthStrategy:                   authStrategy,
			RevokeCredentialsOnShutdown:    agentConfig.Infisical.RevokeCredentialsOnShutdown,
			RetryConfig:                    agentConfig.Infisical.RetryConfig,
		})

		tm.cacheManager, err = NewCacheManager(ctx, &agentConfig.Cache)
		if err != nil {
			log.Error().Msgf("unable to setup cache manager: %v", err)
			cancel()
			return
		}
		tm.dynamicSecretLeases = NewDynamicSecretLeaseManager(tm.cacheManager, tm.SdkRetryConfig())

		go tm.ManageTokenLifecycle()

		if len(agentConfig.Certificates) > 0 {
			go func() {
				for {
					if tm.getTokenUnsafe() != "" {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}

				httpClient, err := tm.createAuthenticatedClient()
				if err != nil {
					log.Error().Msgf("failed to create authenticated client for name resolution: %v", err)
					return
				}

				err = resolveCertificateNameReferences(&agentConfig.Certificates, httpClient)
				if err != nil {
					log.Error().Msgf("failed to resolve certificate name references: %v", err)
					return
				}

				for i := range tm.certificates {
					for j := range agentConfig.Certificates {
						if tm.certificates[i].ID == j+1 {
							tm.certificates[i].Certificate = agentConfig.Certificates[j]
							break
						}
					}
				}
			}()
		}

		if len(tm.certificates) > 0 {
			log.Info().Msg("certificate management engine starting...")
			go tm.MonitorCertificates(ctx)
		}

		for {
			select {
			case <-tokenRefreshNotifier:
				go tm.WriteTokenToFiles()
			case <-sigChan:
				tm.isShuttingDown = true
				tm.cancelContext()
				log.Info().Msg("certificate management agent is gracefully shutting down...")
				cancel()

				exitCode := 0

				if !tm.exitAfterAuth && tm.revokeCredentialsOnShutdown {

					done := make(chan error, 1)

					go func() {
						done <- tm.RevokeCredentials()
					}()

					select {
					case err := <-done:
						if err != nil {
							log.Error().Msgf("unable to revoke credentials [err=%v]", err)
							exitCode = 1
						}
					case <-time.After(5 * time.Minute):
						log.Warn().Msg("credential revocation timed out after 5 minutes, forcing exit")
						exitCode = 1
					}

				}

				os.Exit(exitCode)
			}
		}

	},
}

func init() {
	agentCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		command.Flags().MarkHidden("domain")
		command.Parent().HelpFunc()(command, strings)
	})
	agentCmd.Flags().String("config", "agent-config.yaml", "The path to agent config yaml file")

	certManagerAgentCmd.Flags().String("config", "certificate-agent-config.yaml", "The path to certificate agent config yaml file")
	certManagerAgentCmd.Flags().BoolP("verbose", "v", false, "Enable verbose logging for certificate management agent")
	certManagerCmd.AddCommand(certManagerAgentCmd)

	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(certManagerCmd)
}
