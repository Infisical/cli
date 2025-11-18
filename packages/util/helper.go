package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"path/filepath"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/models"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	RELAY_CACHE_FILE = "/var/lib/infisical/cached_relay"
)

func GetRelayName(cmd *cobra.Command, forceRefetch bool, accessToken string) (string, error) {
	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return "", err
	}
	httpClient.SetAuthToken(accessToken)

	relayName, err := GetCmdFlagOrEnvWithDefaultValue(cmd, "relay", []string{"INFISICAL_RELAY_NAME"}, "")
	if err != nil {
		return "", fmt.Errorf("unable to parse relay flag: %v", err)
	}
	if relayName != "" {
		return relayName, nil
	}

	allRelays, err := api.CallGetRelays(httpClient)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to call GetRelays API")
		return "", fmt.Errorf("failed to fetch relays from platform: %w", err)
	}
	if len(allRelays) == 0 {
		return "", fmt.Errorf("no relays available from the platform")
	}

	// filter for healthy relays
	var healthyRelays []api.Relay
	for _, relay := range allRelays {
		if time.Since(relay.Heartbeat) < time.Hour {
			healthyRelays = append(healthyRelays, relay)
		}
	}

	if len(healthyRelays) == 0 {
		return "", fmt.Errorf("no healthy relays available")
	}

	// check if a cached relay is still healthy
	if !forceRefetch {
		cachedRelayNameBytes, err := os.ReadFile(RELAY_CACHE_FILE)
		if err == nil {
			cachedRelayName := string(cachedRelayNameBytes)
			if cachedRelayName != "" {
				var cachedRelayInfo *api.Relay
				for i := range healthyRelays {
					if healthyRelays[i].Name == cachedRelayName {
						cachedRelayInfo = &healthyRelays[i]
						break
					}
				}

				if cachedRelayInfo != nil {
					// ping the cached relay to confirm it's reachable
					address := fmt.Sprintf("%s:8443", cachedRelayInfo.Host)
					conn, err := net.DialTimeout("tcp", address, 5*time.Second)
					if err == nil {
						conn.Close()
						log.Debug().Str("relay", cachedRelayName).Msg("Using valid and responsive cached relay")
						return cachedRelayName, nil
					}
					log.Debug().Str("relay", cachedRelayName).Err(err).Msg("Cached relay is healthy but failed to respond to ping, finding a new one")
				} else {
					log.Debug().Str("relay", cachedRelayName).Msg("Cached relay is no longer healthy, finding a new one")
				}
			}
		}
	}

	var healthyOrgRelays []api.Relay
	var healthyInstanceRelays []api.Relay
	for _, r := range healthyRelays {
		if r.OrgId != nil {
			healthyOrgRelays = append(healthyOrgRelays, r)
		} else {
			healthyInstanceRelays = append(healthyInstanceRelays, r)
		}
	}

	type pingResult struct {
		relay   api.Relay
		latency time.Duration
		err     error
	}

	findBestByPing := func(relaysToPing []api.Relay) (*api.Relay, time.Duration) {
		if len(relaysToPing) == 0 {
			return nil, 0
		}

		resultsChan := make(chan pingResult, len(relaysToPing))
		var wg sync.WaitGroup

		for _, relay := range relaysToPing {
			wg.Add(1)
			go func(r api.Relay) {
				defer wg.Done()
				address := fmt.Sprintf("%s:8443", r.Host)
				start := time.Now()

				conn, err := net.DialTimeout("tcp", address, 5*time.Second)
				latency := time.Since(start)

				if err == nil {
					conn.Close()
				}
				resultsChan <- pingResult{relay: r, latency: latency, err: err}
			}(relay)
		}

		go func() {
			wg.Wait()
			close(resultsChan)
		}()

		var bestRelay *api.Relay
		minLatency := time.Duration(1<<63 - 1)

		for result := range resultsChan {
			if result.err != nil {
				log.Debug().Err(result.err).Str("relay", result.relay.Name).Msg("Failed to ping relay")
				continue
			}
			log.Debug().Str("relay", result.relay.Name).Dur("latency", result.latency).Msg("Successfully pinged relay")
			if result.latency < minLatency {
				minLatency = result.latency
				currentRelay := result.relay
				bestRelay = &currentRelay
			}
		}
		return bestRelay, minLatency
	}

	var bestRelay *api.Relay
	var minLatency time.Duration

	if len(healthyOrgRelays) > 0 {
		log.Debug().Msg("Prioritizing healthy organization relays by pinging")
		bestRelay, minLatency = findBestByPing(healthyOrgRelays)
	}

	if bestRelay == nil && len(healthyInstanceRelays) > 0 {
		if len(healthyOrgRelays) > 0 {
			log.Debug().Msg("All organization relays failed to respond, falling back to instance relays")
		} else {
			log.Debug().Msg("No healthy organization relays available, using instance relays")
		}
		bestRelay, minLatency = findBestByPing(healthyInstanceRelays)
	}

	var chosenRelay api.Relay
	if bestRelay == nil {
		log.Warn().Msg("Could not determine best relay by ping, selecting a random healthy relay")
		log.Debug().Int("healthy_relays", len(healthyRelays)).Msg("All pings to healthy relays failed. Check network connectivity.")

		if len(healthyOrgRelays) > 0 {
			log.Debug().Msg("Selecting a random healthy organization relay")
			chosenRelay = healthyOrgRelays[rand.Intn(len(healthyOrgRelays))]
		} else {
			log.Debug().Msg("No healthy organization relays available, selecting a random healthy instance relay")
			chosenRelay = healthyInstanceRelays[rand.Intn(len(healthyInstanceRelays))]
		}
	} else {
		chosenRelay = *bestRelay
		log.Debug().Str("relay", chosenRelay.Name).Dur("latency", minLatency).Msg("Selected best relay by ping")
	}

	// cache the chosen relay
	err = os.MkdirAll(filepath.Dir(RELAY_CACHE_FILE), 0755)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create cache directory for relay")
	} else {
		err = os.WriteFile(RELAY_CACHE_FILE, []byte(chosenRelay.Name), 0644)
		if err != nil {
			log.Error().Err(err).Str("relayName", chosenRelay.Name).Msg("Failed to cache relay name")
		}
	}

	return chosenRelay.Name, nil
}

type DecodedSymmetricEncryptionDetails = struct {
	Cipher []byte
	IV     []byte
	Tag    []byte
	Key    []byte
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GetBase64DecodedSymmetricEncryptionDetails(key string, cipher string, IV string, tag string) (DecodedSymmetricEncryptionDetails, error) {
	cipherx, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return DecodedSymmetricEncryptionDetails{}, fmt.Errorf("Base64DecodeSymmetricEncryptionDetails: Unable to decode cipher text [err=%v]", err)
	}

	keyx, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return DecodedSymmetricEncryptionDetails{}, fmt.Errorf("Base64DecodeSymmetricEncryptionDetails: Unable to decode key [err=%v]", err)
	}

	IVx, err := base64.StdEncoding.DecodeString(IV)
	if err != nil {
		return DecodedSymmetricEncryptionDetails{}, fmt.Errorf("Base64DecodeSymmetricEncryptionDetails: Unable to decode IV [err=%v]", err)
	}

	tagx, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return DecodedSymmetricEncryptionDetails{}, fmt.Errorf("Base64DecodeSymmetricEncryptionDetails: Unable to decode tag [err=%v]", err)
	}

	return DecodedSymmetricEncryptionDetails{
		Key:    keyx,
		Cipher: cipherx,
		IV:     IVx,
		Tag:    tagx,
	}, nil
}

// Helper function to sort the secrets by key so we can create a consistent output
func SortSecretsByKeys(secrets []models.SingleEnvironmentVariable) []models.SingleEnvironmentVariable {
	sort.Slice(secrets, func(i, j int) bool {
		return secrets[i].Key < secrets[j].Key
	})
	return secrets
}

func IsSecretEnvironmentValid(env string) bool {
	if env == "prod" || env == "dev" || env == "test" || env == "staging" {
		return true
	}
	return false
}

func IsSecretTypeValid(s string) bool {
	if s == "personal" || s == "shared" {
		return true
	}
	return false
}

func GetInfisicalToken(cmd *cobra.Command) (token *models.TokenDetails, err error) {
	infisicalToken, err := cmd.Flags().GetString("token")

	if err != nil {
		return nil, err
	}

	var source = "--token flag"

	if infisicalToken == "" { // If no flag is passed, we first check for the universal auth access token env variable.
		infisicalToken = os.Getenv(INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME)
		source = fmt.Sprintf("%s environment variable", INFISICAL_UNIVERSAL_AUTH_ACCESS_TOKEN_NAME)

		if infisicalToken == "" { // If it's still empty after the first env check, we check for the service token env variable.
			infisicalToken = os.Getenv(INFISICAL_TOKEN_NAME)
			source = fmt.Sprintf("%s environment variable", INFISICAL_TOKEN_NAME)
		}

		if infisicalToken == "" { // if its still empty, check for the `TOKEN` environment variable (for gateway helm)
			infisicalToken = os.Getenv(INFISICAL_GATEWAY_TOKEN_NAME_LEGACY)
			source = fmt.Sprintf("%s environment variable", INFISICAL_GATEWAY_TOKEN_NAME_LEGACY)
		}
	}

	if infisicalToken == "" { // If it's empty, we return nothing at all.
		return nil, nil
	}

	if strings.HasPrefix(infisicalToken, "st.") {
		return &models.TokenDetails{
			Type:   SERVICE_TOKEN_IDENTIFIER,
			Token:  infisicalToken,
			Source: source,
		}, nil
	}

	return &models.TokenDetails{
		Type:   UNIVERSAL_AUTH_TOKEN_IDENTIFIER,
		Token:  infisicalToken,
		Source: source,
	}, nil

}

func UniversalAuthLogin(clientId string, clientSecret string) (api.UniversalAuthLoginResponse, error) {
	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return api.UniversalAuthLoginResponse{}, err
	}

	httpClient.SetRetryCount(10000).
		SetRetryMaxWaitTime(20 * time.Second).
		SetRetryWaitTime(5 * time.Second)

	tokenResponse, err := api.CallUniversalAuthLogin(httpClient, api.UniversalAuthLoginRequest{ClientId: clientId, ClientSecret: clientSecret})
	if err != nil {
		return api.UniversalAuthLoginResponse{}, err
	}

	return tokenResponse, nil
}

func RenewMachineIdentityAccessToken(accessToken string) (string, error) {

	httpClient, err := GetRestyClientWithCustomHeaders()
	if err != nil {
		return "", err
	}

	httpClient.SetRetryCount(10000).
		SetRetryMaxWaitTime(20 * time.Second).
		SetRetryWaitTime(5 * time.Second)

	request := api.UniversalAuthRefreshRequest{
		AccessToken: accessToken,
	}

	tokenResponse, err := api.CallMachineIdentityRefreshAccessToken(httpClient, request)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

// Checks if the passed in email already exists in the users slice
func ConfigContainsEmail(users []models.LoggedInUser, email string) bool {
	for _, value := range users {
		if value.Email == email {
			return true
		}
	}
	return false
}

func RequireLogin() {
	// get the config file that stores the current logged in user email
	configFile, _ := GetConfigFile()

	if configFile.LoggedInUserEmail == "" {
		EstablishUserLoginSession()
	}
}

func IsLoggedIn() bool {
	configFile, _ := GetConfigFile()
	return configFile.LoggedInUserEmail != ""
}

func RequireServiceToken() {
	serviceToken := os.Getenv(INFISICAL_TOKEN_NAME)
	if serviceToken == "" {
		PrintErrorMessageAndExit("No service token is found in your terminal")
	}
}

func RequireLocalWorkspaceFile() {
	workspaceFilePath, _ := FindWorkspaceConfigFile()
	if workspaceFilePath == "" {
		PrintErrorMessageAndExit("It looks you have not yet connected this project to Infisical", "To do so, run [infisical init] then run your command again")
	}

	workspaceFile, err := GetWorkSpaceFromFile()
	if err != nil {
		HandleError(err, "Unable to read your project configuration, please try initializing this project again.", "Run [infisical init]")
	}

	if workspaceFile.WorkspaceId == "" {
		PrintErrorMessageAndExit("Your project id is missing in your local config file. Please add it or run again [infisical init]")
	}
}

func ValidateWorkspaceFile(projectConfigFilePath string) {
	workspaceFilePath, err := GetWorkSpaceFromFilePath(projectConfigFilePath)
	if err != nil {
		PrintErrorMessageAndExit(fmt.Sprintf("error reading your project config %v", err))
	}

	if workspaceFilePath.WorkspaceId == "" {
		PrintErrorMessageAndExit("Your project id is missing in your local config file. Please add it or run again [infisical init]")
	}
}

func GetHashFromStringList(list []string) string {
	hash := sha256.New()

	for _, item := range list {
		hash.Write([]byte(item))
	}

	sum := sha256.Sum256(hash.Sum(nil))
	return fmt.Sprintf("%x", sum)
}

// execCmd is a struct that holds the command and arguments to be executed.
// By using this struct, we can easily mock the command and arguments.
type execCmd struct {
	cmd  string
	args []string
}

var getCurrentBranchCmd = execCmd{
	cmd:  "git",
	args: []string{"symbolic-ref", "--short", "HEAD"},
}

func getCurrentBranch() (string, error) {
	cmd := exec.Command(getCurrentBranchCmd.cmd, getCurrentBranchCmd.args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return path.Base(strings.TrimSpace(out.String())), nil
}

func AppendAPIEndpoint(address string) string {
	// if it's empty return as it is
	// Ensure the address does not already end with "/api"
	if address == "" || strings.HasSuffix(address, "/api") {
		return address
	}

	// Check if the address ends with a slash and append accordingly
	if address[len(address)-1] == '/' {
		return address + "api"
	}
	return address + "/api"
}

func ReadFileAsString(filePath string) (string, error) {
	fileBytes, err := os.ReadFile(filePath)

	if err != nil {
		return "", err
	}

	return string(fileBytes), nil

}

func GetEnvVarOrFileContent(envName string, filePath string) (string, error) {
	// First check if the environment variable is set
	if envVarValue := os.Getenv(envName); envVarValue != "" {
		return envVarValue, nil
	}

	// If it's not set, try to read the file
	fileContent, err := ReadFileAsString(filePath)

	if err != nil {
		return "", fmt.Errorf("unable to read file content from file path '%s' [err=%v]", filePath, err)
	}

	return strings.TrimSpace(fileContent), nil
}

func GetCmdFlagOrEnv(cmd *cobra.Command, flag string, envNames []string) (string, error) {
	value, flagsErr := cmd.Flags().GetString(flag)
	if flagsErr != nil {
		return "", flagsErr
	}
	if value == "" {
		for _, env := range envNames {
			value = strings.TrimSpace(os.Getenv(env))
			if value != "" {
				log.Debug().Str("env", env).Str("flag", flag).Msg("Using value from environment variable for flag")
				break
			}
		}
	}
	if value == "" {
		return "", fmt.Errorf("please provide %s flag", flag)
	}
	return value, nil
}

func GetCmdFlagOrEnvWithDefaultValue(cmd *cobra.Command, flag string, envNames []string, defaultValue string) (string, error) {
	value, flagsErr := cmd.Flags().GetString(flag)
	if flagsErr != nil {
		return "", flagsErr
	}
	if value == "" {
		for _, env := range envNames {
			value = strings.TrimSpace(os.Getenv(env))
			if value != "" {
				break
			}
		}
	}
	if value == "" {
		return defaultValue, nil
	}

	return value, nil
}

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func GenerateETagFromSecrets(secrets []models.SingleEnvironmentVariable) string {
	sortedSecrets := SortSecretsByKeys(secrets)
	content := []byte{}

	for _, secret := range sortedSecrets {
		content = append(content, []byte(secret.Key)...)
		content = append(content, []byte(secret.Value)...)
	}

	hash := sha256.Sum256(content)
	return fmt.Sprintf(`"%s"`, hex.EncodeToString(hash[:]))
}

func IsDevelopmentMode() bool {
	return CLI_VERSION == "devel"
}
