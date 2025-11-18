/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/template"
	"time"

	"github.com/dgraph-io/badger/v3"
	infisicalSdk "github.com/infisical/go-sdk"
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

const DYNAMIC_SECRET_LEASE_TEMPLATE = "dynamic-secret-lease-%s-%s-%s-%s-%d"

// duration to reduce from expiry of dynamic leases so that it gets triggered before expiry
const DYNAMIC_SECRET_PRUNE_EXPIRE_BUFFER = -15

// duration remove leases from the cache before they expire when the agent is first started with existing leases in the cache.
// if a lease is expired, or expires in 2 minutes or less, it will be deleted from the cache and a new lease will be created.
var CACHE_LEASE_EXPIRE_BUFFER = 30 * time.Second

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

type Config struct {
	Infisical InfisicalConfig `yaml:"infisical"`
	Auth      AuthConfig      `yaml:"auth"`
	Sinks     []Sink          `yaml:"sinks"`
	Cache     CacheConfig     `yaml:"cache,omitempty"`
	Templates []Template      `yaml:"templates"`
}

type TemplateWithID struct {
	ID       int
	Template Template
}

type InfisicalConfig struct {
	Address                     string `yaml:"address"`
	ExitAfterAuth               bool   `yaml:"exit-after-auth"`
	RevokeCredentialsOnShutdown bool   `yaml:"revoke-credentials-on-shutdown"`
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

type DynamicSecretLease struct {
	LeaseID     string
	ExpireAt    time.Time
	Environment string
	SecretPath  string
	Slug        string
	ProjectSlug string
	Data        map[string]interface{}
	TemplateID  int
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

	encryptionKey := sha256.Sum256(serviceAccountToken)

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
	leases       []DynamicSecretLease
	mutex        sync.Mutex
	cacheManager *CacheManager
}

func (d *DynamicSecretLeaseManager) WriteLeaseToCache(lease *DynamicSecretLease, templateId int) {

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
		templateId,
	)

	ttl := lease.ExpireAt.Sub(time.Now())

	log.Info().Msgf("[cache]: writing dynamic secret lease to cache: [cache-key=%s] [entry-ttl=%s]", cacheKey, ttl.String())

	if err := d.cacheManager.WriteToCache(cacheKey, lease, &ttl); err != nil {
		log.Error().Msgf("[cache]: unable to write dynamic secret lease to cache because %v", err)
	} else {
		log.Info().Msgf("[cache]: dynamic secret lease written to cache: %s", cacheKey)
	}
}

func (d *DynamicSecretLeaseManager) ReadLeaseFromCache(projectSlug, environment, secretPath, slug string, templateId int) *DynamicSecretLease {

	if d.cacheManager == nil || !d.cacheManager.IsEnabled {
		return nil
	}

	cacheKey := fmt.Sprintf(DYNAMIC_SECRET_LEASE_TEMPLATE, projectSlug, environment, secretPath, slug, templateId)
	var lease *DynamicSecretLease
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

func (d *DynamicSecretLeaseManager) DeleteLeaseFromCache(projectSlug, environment, secretPath, slug string, templateId int) error {
	if d.cacheManager == nil || !d.cacheManager.IsEnabled {
		return nil
	}

	cacheKey := fmt.Sprintf(DYNAMIC_SECRET_LEASE_TEMPLATE, projectSlug, environment, secretPath, slug, templateId)
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

	var cachedLeases []DynamicSecretLease
	for cacheKey, leaseData := range allCacheKeys {
		if strings.HasPrefix(cacheKey, "dynamic-secret-lease-") {
			// Marshal back to JSON and unmarshal into the correct type
			jsonData, err := json.Marshal(leaseData)
			if err != nil {
				log.Warn().Msgf("[cache]: failed to marshal cached lease data for key %s: %v", cacheKey, err)
				continue
			}

			var lease DynamicSecretLease
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
			"[cache]: checking cached lease: [project=%s], [env=%s], [path=%s], [slug=%s], [template-id=%d]",
			cachedLease.ProjectSlug,
			cachedLease.Environment,
			cachedLease.SecretPath,
			cachedLease.Slug,
			cachedLease.TemplateID,
		)

		// check if a lease with the same configuration exists (not comparing LeaseID since that changes on refresh)
		found := slices.ContainsFunc(d.leases, func(s DynamicSecretLease) bool {
			match := s.ProjectSlug == cachedLease.ProjectSlug &&
				s.Environment == cachedLease.Environment &&
				s.SecretPath == cachedLease.SecretPath &&
				s.Slug == cachedLease.Slug &&
				s.TemplateID == cachedLease.TemplateID

			if match {
				log.Debug().Msgf("[cache]: found matching active lease: [project=%s], [env=%s], [path=%s], [slug=%s], [template-id=%d]",
					s.ProjectSlug,
					s.Environment,
					s.SecretPath,
					s.Slug,
					s.TemplateID,
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
				cachedLease.TemplateID,
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

	d.leases = slices.DeleteFunc(d.leases, func(s DynamicSecretLease) bool {
		shouldDelete := time.Now().After(s.ExpireAt.Add(DYNAMIC_SECRET_PRUNE_EXPIRE_BUFFER * time.Second))

		if shouldDelete {
			if err := d.DeleteLeaseFromCache(s.ProjectSlug, s.Environment, s.SecretPath, s.Slug, s.TemplateID); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}
		}
		return shouldDelete
	})
}

// appendUnsafe can be used if you already hold the lock
func (d *DynamicSecretLeaseManager) appendUnsafe(lease DynamicSecretLease) {

	index := slices.IndexFunc(d.leases, func(s DynamicSecretLease) bool {
		if lease.SecretPath == s.SecretPath && lease.Environment == s.Environment && lease.ProjectSlug == s.ProjectSlug && lease.Slug == s.Slug && lease.LeaseID == s.LeaseID {
			return true
		}
		return false
	})

	if index != -1 {
		d.leases[index].TemplateID = lease.TemplateID
		return
	}

	d.leases = append(d.leases, lease)

	d.WriteLeaseToCache(&lease, lease.TemplateID)

}

func (d *DynamicSecretLeaseManager) Append(lease DynamicSecretLease) {

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.appendUnsafe(lease)
}

func (d *DynamicSecretLeaseManager) RegisterTemplate(projectSlug, environment, secretPath, slug string, templateId int) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	index := slices.IndexFunc(d.leases, func(lease DynamicSecretLease) bool {
		if lease.SecretPath == secretPath && lease.Environment == environment && lease.ProjectSlug == projectSlug && lease.Slug == slug && lease.TemplateID == templateId {
			return true
		}

		return false
	})

	if index != -1 {
		d.leases[index].TemplateID = templateId
	}
}

func (d *DynamicSecretLeaseManager) GetLease(accessToken, projectSlug, environment, secretPath, slug string, templateId int) *DynamicSecretLease {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// first try to get from in-memory storage

	for _, lease := range d.leases {
		if lease.SecretPath == secretPath && lease.Environment == environment && lease.ProjectSlug == projectSlug && lease.Slug == slug && lease.TemplateID == templateId {
			return &lease
		}
	}

	// if no lease is found in in-memory storage, try to get from cache

	log.Info().Msgf("[cache]: no lease found, fetching from cache")
	leaseFromCache := d.ReadLeaseFromCache(projectSlug, environment, secretPath, slug, templateId)
	log.Debug().Msgf("[cache]: lease from cache: %+v", leaseFromCache)

	if leaseFromCache != nil {

		// try to get the lease from the API

		// ? question(daniel): should we trust the cache more, and avoid calling the API to see if the lease still exists?
		// ? we do this to ensure that the lease wasn't deleted while the agent was not running

		dynamicSecretLease, err := util.GetDynamicSecretLease(accessToken, leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.LeaseID)
		if err != nil {

			log.Warn().Msgf("[cache]: error: %+v", err)

			// lease not found in API, delete it from cache and return nil
			if errors.Is(err, api.ErrNotFound) {
				log.Warn().Msgf("dynamic secret lease does not exist, deleting from cache: [lease-id=%s]", leaseFromCache.LeaseID)
				if err := d.DeleteLeaseFromCache(leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.Slug, leaseFromCache.TemplateID); err != nil {
					log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
				}

				return nil
			}

			// lease is found in cache but not in the the API, and the API returned a non 404-error. We should attempt to revoke it
			// at this point we know that we should be able to reach the API because we've done authentication successfully
			log.Warn().Msgf("unable to get dynamic secret lease from API. Revoking lease from cache: [lease-id=%s]", leaseFromCache.LeaseID)
			if err := d.DeleteLeaseFromCache(leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.Slug, leaseFromCache.TemplateID); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}

			if err := revokeDynamicSecretLease(accessToken, leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.LeaseID); err != nil {
				log.Warn().Msgf("unable to revoke dynamic secret lease %s: %v", leaseFromCache.LeaseID, err)
				return nil
			}

			return nil
		}

		// lease is expired or about to expire, delete from cache and attempt to revoke it
		if dynamicSecretLease.Lease.ExpireAt.Before(time.Now().Add(2 * time.Minute)) {
			log.Warn().Msgf("dynamic secret lease is expired or about to expire, deleting from cache: [lease-id=%s]", leaseFromCache.LeaseID)
			if err := d.DeleteLeaseFromCache(leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.Slug, leaseFromCache.TemplateID); err != nil {
				log.Warn().Msgf("[cache]: unable to delete lease from cache: %v", err)
			}

			if err := revokeDynamicSecretLease(accessToken, leaseFromCache.ProjectSlug, leaseFromCache.Environment, leaseFromCache.SecretPath, leaseFromCache.LeaseID); err != nil {
				log.Warn().Msgf("unable to revoke expired dynamic secret lease %s: %v. Non-critical, the lease is already expired or will expire automatically within the next 2 minutes.", leaseFromCache.LeaseID, err)
				return nil
			}

			return nil
		}

		// we call appendUnsafe because we already hold the lock, and if we call Append directly we'll get a deadlock
		d.appendUnsafe(*leaseFromCache)

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

func NewDynamicSecretLeaseManager(sigChan chan os.Signal, cacheManager *CacheManager) *DynamicSecretLeaseManager {
	manager := &DynamicSecretLeaseManager{
		cacheManager: cacheManager,
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

func ParseAgentConfig(configFile []byte) (*Config, error) {
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

func secretTemplateFunction(accessToken string, existingEtag string, currentEtag *string) func(string, string, string, ...string) ([]models.SingleEnvironmentVariable, error) {
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

		if existingEtag != res.Etag {
			*currentEtag = res.Etag
		}

		return res.Secrets, nil
	}
}

func getSingleSecretTemplateFunction(accessToken string, existingEtag string, currentEtag *string) func(string, string, string, string) (models.SingleEnvironmentVariable, error) {
	return func(projectID, envSlug, secretPath, secretName string) (models.SingleEnvironmentVariable, error) {
		secret, requestEtag, err := util.GetSinglePlainTextSecretByNameV3(accessToken, projectID, envSlug, secretPath, secretName)
		if err != nil {
			return models.SingleEnvironmentVariable{}, err
		}

		if existingEtag != requestEtag {
			*currentEtag = requestEtag
		}

		return secret, nil
	}
}

func dynamicSecretTemplateFunction(accessToken string, dynamicSecretManager *DynamicSecretLeaseManager, templateId int, currentEtag *string) func(...string) (map[string]interface{}, error) {

	return func(args ...string) (map[string]interface{}, error) {
		argLength := len(args)
		if argLength != 4 && argLength != 5 {
			return nil, fmt.Errorf("invalid arguments found for dynamic-secret function. Check template %d", templateId)
		}

		projectSlug, envSlug, secretPath, slug, ttl := args[0], args[1], args[2], args[3], ""
		if argLength == 5 {
			ttl = args[4]
		}
		dynamicSecretData := dynamicSecretManager.GetLease(accessToken, projectSlug, envSlug, secretPath, slug, templateId)

		// if a lease is found (either in memory or in cache), we register the template and return the data
		if dynamicSecretData != nil {
			dynamicSecretManager.RegisterTemplate(projectSlug, envSlug, secretPath, slug, templateId)
			return dynamicSecretData.Data, nil
		}

		// if there's no lease (either in memory or in cache), we create a new lease
		res, err := util.CreateDynamicSecretLease(accessToken, projectSlug, envSlug, secretPath, slug, ttl)
		if err != nil {
			return nil, err
		}

		// we set an arbitrary etag to ensure that the template is re-rendered when a new lease is created
		*currentEtag = util.GenerateRandomString(32)

		dynamicSecretManager.Append(DynamicSecretLease{LeaseID: res.Lease.Id, ExpireAt: res.Lease.ExpireAt, Environment: envSlug, SecretPath: secretPath, Slug: slug, ProjectSlug: projectSlug, Data: res.Data, TemplateID: templateId})

		return res.Data, nil
	}
}

func ProcessTemplate(templateId int, templatePath string, data interface{}, accessToken string, existingEtag string, currentEtag *string, dynamicSecretManager *DynamicSecretLeaseManager) (*bytes.Buffer, error) {

	// custom template function to fetch secrets from Infisical
	secretFunction := secretTemplateFunction(accessToken, existingEtag, currentEtag)
	dynamicSecretFunction := dynamicSecretTemplateFunction(accessToken, dynamicSecretManager, templateId, currentEtag)
	getSingleSecretFunction := getSingleSecretTemplateFunction(accessToken, existingEtag, currentEtag)
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

func ProcessBase64Template(templateId int, encodedTemplate string, data interface{}, accessToken string, existingEtag string, currentEtag *string, dynamicSecretLeaseManager *DynamicSecretLeaseManager) (*bytes.Buffer, error) {
	// custom template function to fetch secrets from Infisical
	decoded, err := base64.StdEncoding.DecodeString(encodedTemplate)
	if err != nil {
		return nil, err
	}

	templateString := string(decoded)

	secretFunction := secretTemplateFunction(accessToken, existingEtag, currentEtag) // TODO: Fix this
	dynamicSecretFunction := dynamicSecretTemplateFunction(accessToken, dynamicSecretLeaseManager, templateId, currentEtag)
	funcs := template.FuncMap{
		"secret":         secretFunction,
		"dynamic_secret": dynamicSecretFunction,
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

func ProcessLiteralTemplate(templateId int, templateString string, data interface{}, accessToken string, existingEtag string, currentEtag *string, dynamicSecretLeaseManager *DynamicSecretLeaseManager) (*bytes.Buffer, error) {

	secretFunction := secretTemplateFunction(accessToken, existingEtag, currentEtag)
	dynamicSecretFunction := dynamicSecretTemplateFunction(accessToken, dynamicSecretLeaseManager, templateId, currentEtag)
	funcs := template.FuncMap{
		"secret":         secretFunction,
		"dynamic_secret": dynamicSecretFunction,
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
	accessToken              string
	accessTokenTTL           time.Duration
	accessTokenMaxTTL        time.Duration
	accessTokenFetchedTime   time.Time
	accessTokenRefreshedTime time.Time
	mutex                    sync.Mutex
	filePaths                []Sink // Store file paths if needed
	templates                []TemplateWithID
	dynamicSecretLeases      *DynamicSecretLeaseManager
	cacheManager             *CacheManager
	authConfigBytes          []byte
	authStrategy             util.AuthStrategyType

	newAccessTokenNotificationChan  chan bool
	cachedUniversalAuthClientSecret string
	templateFirstRenderOnce         map[int]*sync.Once // Track first render per template
	exitAfterAuth                   bool
	revokeCredentialsOnShutdown     bool

	isShuttingDown bool

	infisicalClient infisicalSdk.InfisicalClientInterface
}

type NewAgentMangerOptions struct {
	FileDeposits []Sink
	Templates    []Template

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

	return &AgentManager{
		filePaths: options.FileDeposits,
		templates: templates,

		authConfigBytes: options.AuthConfigBytes,
		authStrategy:    options.AuthStrategy,

		newAccessTokenNotificationChan: options.NewAccessTokenNotificationChan,
		exitAfterAuth:                  options.ExitAfterAuth,
		revokeCredentialsOnShutdown:    options.RevokeCredentialsOnShutdown,
		templateFirstRenderOnce:        templateFirstRenderOnce,

		infisicalClient: infisicalSdk.NewInfisicalClient(context.Background(), infisicalSdk.Config{
			SiteUrl:          config.INFISICAL_URL,
			UserAgent:        api.USER_AGENT, // ? Should we perhaps use a different user agent for the Agent for better analytics?
			AutoTokenRefresh: false,
			CustomHeaders:    customHeaders,
		}),
	}

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

	return tm.infisicalClient.Auth().UniversalAuthLogin(clientID, clientSecret)
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

	credential, err := authStrategies[tm.authStrategy]()

	if err != nil {
		return err
	}

	accessTokenTTL := time.Duration(credential.ExpiresIn * int64(time.Second))
	accessTokenMaxTTL := time.Duration(credential.AccessTokenMaxTTL * int64(time.Second))

	if accessTokenTTL <= time.Duration(5)*time.Second {
		util.PrintErrorMessageAndExit("At this time, agent does not support refresh of tokens with 5 seconds or less ttl. Please increase access token ttl and try again")
	}

	tm.accessTokenFetchedTime = time.Now()
	tm.SetToken(credential.AccessToken, accessTokenTTL, accessTokenMaxTTL)

	return nil
}

func revokeDynamicSecretLease(accessToken, projectSlug, environment, secretPath, leaseID string) error {
	customHeaders, err := util.GetInfisicalCustomHeadersMap()
	if err != nil {
		return fmt.Errorf("unable to get custom headers: %v", err)
	}

	temporaryInfisicalClient := infisicalSdk.NewInfisicalClient(context.Background(), infisicalSdk.Config{
		SiteUrl:          config.INFISICAL_URL,
		UserAgent:        api.USER_AGENT,
		AutoTokenRefresh: false,
		CustomHeaders:    customHeaders,
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

	for _, lease := range dynamicSecretLeases {

		err = revokeDynamicSecretLease(token, lease.ProjectSlug, lease.Environment, lease.SecretPath, lease.LeaseID)

		if err != nil {

			if strings.Contains(err.Error(), "status-code=404") {
				log.Info().Msgf("dynamic secret lease %s not found, skipping", lease.LeaseID)
				continue
			}

			log.Error().Msgf("unable to revoke dynamic secret lease %s: %v", lease.LeaseID, err)
			continue
		}

		// write to the lease file, and make it an empty file

		// find the template that this lease is associated with
		templateIndex := slices.IndexFunc(tm.templates, func(t TemplateWithID) bool {
			return t.ID == lease.TemplateID
		})

		if templateIndex != -1 {
			template := tm.templates[templateIndex]
			if _, err := os.Stat(template.Template.DestinationPath); !os.IsNotExist(err) {
				if err := os.WriteFile(template.Template.DestinationPath, []byte(""), 0644); err != nil {
					log.Warn().Msgf("unable to erase lease from file '%s' because %v", template.Template.DestinationPath, err)
				}
			}
		}

		log.Info().Msgf("successfully revoked dynamic secret lease [id=%s] [project-slug=%s]", lease.LeaseID, lease.ProjectSlug)
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

		// Calculate next expiry time at 2/3 of the TTL
		nextAccessTokenExpiresInTime := accessTokenRefreshedTime.Add(tm.accessTokenTTL * 2 / 3)

		if tm.accessTokenFetchedTime.IsZero() && tm.accessTokenRefreshedTime.IsZero() {
			// try to fetch token from sink files first
			// if token is found, refresh the token right away and continue from there
			isSavedTokenValid := false
			token := tm.FetchTokenFromFiles()
			if token != "" {

				log.Info().Msg("found existing token in cache, attempting to refresh...")
				err := tm.RefreshAccessToken(token)
				isSavedTokenValid = err == nil

				if isSavedTokenValid {
					log.Info().Msg("token refreshed successfully from saved cache")
					tm.accessTokenFetchedTime = time.Now()
				} else {
					log.Error().Msg("unable to refresh token from saved cache")
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
		nextAccessTokenExpiresInTime = accessTokenRefreshedTime.Add(tm.accessTokenTTL * 2 / 3)
		accessTokenMaxTTLExpiresInTime = tm.accessTokenFetchedTime.Add(tm.accessTokenMaxTTL - (5 * time.Second))

		if nextAccessTokenExpiresInTime.After(accessTokenMaxTTLExpiresInTime) {
			// case: Refreshed so close that the next refresh would occur beyond max ttl
			// Sleep until we're at 2/3 of the remaining time to max TTL
			remainingTime := accessTokenMaxTTLExpiresInTime.Sub(time.Now())
			time.Sleep(remainingTime * 2 / 3)
		} else {
			// Sleep until we're at 2/3 of the TTL
			time.Sleep(tm.accessTokenTTL * 2 / 3)
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

func (tm *AgentManager) WriteTemplateToFile(bytes *bytes.Buffer, template *Template) {
	if err := WriteBytesToFile(bytes, template.DestinationPath); err != nil {
		log.Error().Msgf("template engine: unable to write secrets to path because %s. Will try again on next cycle", err)
		return
	}
	log.Info().Msgf("template engine: secret template at path %s has been rendered and saved to path %s", template.SourcePath, template.DestinationPath)
}

func (tm *AgentManager) MonitorSecretChanges(secretTemplate Template, templateId int, sigChan chan os.Signal, monitoringChan chan bool) {

	pollingInterval := time.Duration(5 * time.Minute)

	if secretTemplate.Config.PollingInterval != "" {
		interval, err := util.ConvertPollingIntervalToTime(secretTemplate.Config.PollingInterval)

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
		case <-sigChan:
			return
		default:
			{
				if tm.isShuttingDown {
					return
				}

				tm.dynamicSecretLeases.Prune()
				token := tm.GetToken()
				if token != "" {
					var processedTemplate *bytes.Buffer
					var err error

					if secretTemplate.SourcePath != "" {
						processedTemplate, err = ProcessTemplate(templateId, secretTemplate.SourcePath, nil, token, existingEtag, &currentEtag, tm.dynamicSecretLeases)
					} else if secretTemplate.TemplateContent != "" {
						processedTemplate, err = ProcessLiteralTemplate(templateId, secretTemplate.TemplateContent, nil, token, existingEtag, &currentEtag, tm.dynamicSecretLeases)
					} else {
						processedTemplate, err = ProcessBase64Template(templateId, secretTemplate.Base64TemplateContent, nil, token, existingEtag, &currentEtag, tm.dynamicSecretLeases)
					}

					if err != nil {
						log.Error().Msgf("unable to process template because %v", err)

						// case: if exit-after-auth is true, it should exit the agent once an error on secret fetching occurs with the appropriate exit code (1)
						// previous behavior would exit after 25 sec with status code 0, even if this step errors
						if tm.exitAfterAuth {
							os.Exit(1)
						}
					} else {
						if (existingEtag != currentEtag) || firstRun {

							tm.WriteTemplateToFile(processedTemplate, &secretTemplate)

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
					if isValid && firstLeaseExpiry.Sub(time.Now()) < pollingInterval {
						waitTime = firstLeaseExpiry.Sub(time.Now())
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
			log.Error().Msgf("Unable to prase %s because %v. Please ensure that is follows the Infisical Agent config structure", configPath, err)
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

		tm := NewAgentManager(NewAgentMangerOptions{
			FileDeposits:                   filePaths,
			Templates:                      agentConfig.Templates,
			AuthConfigBytes:                configBytes,
			NewAccessTokenNotificationChan: tokenRefreshNotifier,
			ExitAfterAuth:                  agentConfig.Infisical.ExitAfterAuth,
			AuthStrategy:                   authStrategy,
			RevokeCredentialsOnShutdown:    agentConfig.Infisical.RevokeCredentialsOnShutdown,
		})

		tm.cacheManager, err = NewCacheManager(ctx, &agentConfig.Cache)
		if err != nil {
			log.Error().Msgf("unable to setup cache manager: %v", err)
			cancel()
			return
		}
		tm.dynamicSecretLeases = NewDynamicSecretLeaseManager(sigChan, tm.cacheManager)

		// start a http server that returns a json object of the whole cache
		if util.IsDevelopmentMode() {

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

		var monitoredTemplatesFinished atomic.Int32

		// when all templates have finished rendering once, we delete the unused leases from the cache.
		go func() {
			for {
				select {
				case <-monitoringChan:
					monitoredTemplatesFinished.Add(1)
					if monitoredTemplatesFinished.Load() == int32(len(tm.templates)) {
						if err := tm.dynamicSecretLeases.DeleteUnusedLeasesFromCache(); err != nil {
							log.Error().Msgf("[template monitor] failed to delete unused leases from cache: %v", err)
						}

						if tm.exitAfterAuth {
							os.Exit(0)
						}
					}
				case <-sigChan:
					return
				}
			}
		}()

		for _, template := range tm.templates {
			log.Info().Msgf("template engine started for template %v...", template.ID)
			go tm.MonitorSecretChanges(template.Template, template.ID, sigChan, monitoringChan)
		}

		for {
			select {
			case <-tokenRefreshNotifier:
				go tm.WriteTokenToFiles()
			case <-sigChan:
				tm.isShuttingDown = true
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

func init() {
	agentCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		command.Flags().MarkHidden("domain")
		command.Parent().HelpFunc()(command, strings)
	})
	agentCmd.Flags().String("config", "agent-config.yaml", "The path to agent config yaml file")
	rootCmd.AddCommand(agentCmd)
}
