package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/zalando/go-keyring"
)

type LoggedInUserDetails struct {
	IsUserLoggedIn  bool
	LoginExpired    bool
	UserCredentials models.UserCredentials
}

func StoreUserCredsInKeyRing(userCred *models.UserCredentials) error {
	userCredMarshalled, err := json.Marshal(userCred)
	if err != nil {
		return fmt.Errorf("StoreUserCredsInKeyRing: something went wrong when marshalling user creds [err=%s]", err)
	}

	err = SetValueInKeyring(userCred.Email, string(userCredMarshalled))
	if err != nil {
		return fmt.Errorf("StoreUserCredsInKeyRing: unable to store user credentials because [err=%s]", err)
	}

	return err
}

func GetUserCredsFromKeyRing(userEmail string) (credentials models.UserCredentials, err error) {
	credentialsValue, err := GetValueInKeyring(userEmail)
	if err != nil {
		if err == keyring.ErrUnsupportedPlatform {
			return models.UserCredentials{}, errors.New("your OS does not support keyring. Consider using a service token https://infisical.com/docs/documentation/platform/token")
		} else if err == keyring.ErrNotFound {
			return models.UserCredentials{}, errors.New("credentials not found in system keyring")
		} else {
			return models.UserCredentials{}, fmt.Errorf("something went wrong, failed to retrieve value from system keyring [error=%v]", err)
		}
	}

	var userCredentials models.UserCredentials

	err = json.Unmarshal([]byte(credentialsValue), &userCredentials)
	if err != nil {
		return models.UserCredentials{}, fmt.Errorf("getUserCredsFromKeyRing: Something went wrong when unmarshalling user creds [err=%s]", err)
	}

	return userCredentials, err
}

func GetCurrentLoggedInUserDetails(setConfigVariables bool) (LoggedInUserDetails, error) {
	if ConfigFileExists() {
		configFile, err := GetConfigFile()
		if err != nil {
			return LoggedInUserDetails{}, fmt.Errorf("getCurrentLoggedInUserDetails: unable to get logged in user from config file [err=%s]", err)
		}

		if configFile.LoggedInUserEmail == "" {
			return LoggedInUserDetails{}, nil
		}

		userCreds, err := GetUserCredsFromKeyRing(configFile.LoggedInUserEmail)
		if err != nil {
			if strings.Contains(err.Error(), "credentials not found in system keyring") {
				return LoggedInUserDetails{}, errors.New("we couldn't find your logged in details, try running [infisical login] then try again")
			} else {
				return LoggedInUserDetails{}, fmt.Errorf("failed to fetch credentials from keyring because [err=%s]", err)
			}
		}

		if setConfigVariables {
			config.INFISICAL_URL_MANUAL_OVERRIDE = config.INFISICAL_URL
			//configFile.LoggedInUserDomain
			//if not empty set as infisical url
			if configFile.LoggedInUserDomain != "" {
				config.INFISICAL_URL = AppendAPIEndpoint(configFile.LoggedInUserDomain)
			}
		}

		isAuthenticated := !IsJWTExpired(userCreds.JTWToken)

		// TODO: add refresh token
		// if !isAuthenticated {
		// 	accessTokenResponse, err := api.CallGetNewAccessTokenWithRefreshToken(httpClient, userCreds.RefreshToken)
		// 	if err == nil && accessTokenResponse.Token != "" {
		// 		isAuthenticated = true
		// 		userCreds.JTWToken = accessTokenResponse.Token
		// 	}
		// }

		if !isAuthenticated {
			return LoggedInUserDetails{
				IsUserLoggedIn:  true, // was logged in
				LoginExpired:    true,
				UserCredentials: userCreds,
			}, nil
		}

		return LoggedInUserDetails{
			IsUserLoggedIn:  true,
			LoginExpired:    false,
			UserCredentials: userCreds,
		}, nil
	} else {
		return LoggedInUserDetails{}, nil
	}
}

func IsJWTExpired(token string) bool {
	parser := jwt.NewParser()
	claims := &jwt.RegisteredClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return true
	}
	if claims.ExpiresAt == nil {
		return true
	}
	// 30-second buffer to avoid race between local check and subsequent API call
	return claims.ExpiresAt.Before(time.Now().Add(30 * time.Second))
}
