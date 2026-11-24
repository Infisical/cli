/*
Copyright (c) 2023 Infisical Inc.
*/
package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"text/template"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/templates"
	"github.com/Infisical/infisical-merge/packages/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// handleK8SecretOutput processes the k8-secret output type by creating a Kubernetes secret
func handleK8SecretOutput(bootstrapResponse api.BootstrapInstanceResponse, k8SecretTemplate, k8SecretName, k8SecretNamespace string) error {
	// Create in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to create in-cluster config: %v", err)
	}

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	templateFuncs := template.FuncMap{
		"encodeBase64": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
	}

	// Parse and execute the template to render the data/stringData section
	tmpl, err := template.New("k8-secret-template").Funcs(templates.CompileTemplateFunctions(templateFuncs)).Parse(k8SecretTemplate)

	if err != nil {
		return fmt.Errorf("failed to parse output template: %v", err)
	}

	var renderedDataSection bytes.Buffer
	err = tmpl.Execute(&renderedDataSection, bootstrapResponse)
	if err != nil {
		return fmt.Errorf("failed to execute output template: %v", err)
	}

	// Parse the rendered template as JSON to validate it's valid
	var dataSection map[string]interface{}
	if err := json.Unmarshal(renderedDataSection.Bytes(), &dataSection); err != nil {
		return fmt.Errorf("template output is not valid JSON: %v", err)
	}

	// Prepare the secret data and stringData maps
	secretData := make(map[string][]byte)
	secretStringData := make(map[string]string)

	// Process the dataSection to separate data and stringData
	if data, exists := dataSection["data"]; exists {
		if dataMap, ok := data.(map[string]interface{}); ok {
			for key, value := range dataMap {
				if strValue, ok := value.(string); ok {
					secretData[key] = []byte(strValue)
				}
			}
		}
	}

	if stringData, exists := dataSection["stringData"]; exists {
		if stringDataMap, ok := stringData.(map[string]interface{}); ok {
			for key, value := range stringDataMap {
				if strValue, ok := value.(string); ok {
					secretStringData[key] = strValue
				}
			}
		}
	}

	// Create the Kubernetes secret object
	k8sSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      k8SecretName,
			Namespace: k8SecretNamespace,
		},
		Type:       corev1.SecretTypeOpaque,
		Data:       secretData,
		StringData: secretStringData,
	}

	ctx := context.Background()
	secretsClient := clientset.CoreV1().Secrets(k8SecretNamespace)

	// Check if secret already exists
	existingSecret, err := secretsClient.Get(ctx, k8SecretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// Secret doesn't exist, create it
			_, err = secretsClient.Create(ctx, k8sSecret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create Kubernetes secret: %v", err)
			}
			log.Info().Msgf("Successfully created Kubernetes secret '%s' in namespace '%s'", k8SecretName, k8SecretNamespace)
		} else {
			return fmt.Errorf("failed to check if Kubernetes secret exists: %v", err)
		}
	} else {
		// Secret exists, update it
		k8sSecret.ObjectMeta.ResourceVersion = existingSecret.ObjectMeta.ResourceVersion
		_, err = secretsClient.Update(ctx, k8sSecret, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update Kubernetes secret: %v", err)
		}
		log.Info().Msgf("Successfully updated Kubernetes secret '%s' in namespace '%s'", k8SecretName, k8SecretNamespace)
	}

	return nil
}

const instanceAlreadySetUpName = "SUPER_ADMIN_INSTANCE_ALREADY_SET_UP"

func isInstanceAlreadySetUp(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest && apiErr.Name == instanceAlreadySetUpName
}

func requiredBootstrapInput(cmd *cobra.Command, flag string, envNames ...string) string {
	value, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, flag, envNames, "")
	if err != nil {
		util.HandleError(err, fmt.Sprintf("Unable to parse flag --%s", flag))
	}
	if value == "" {
		util.PrintErrorMessageAndExit(fmt.Sprintf("%s is required. Pass --%s or set %s.", flag, flag, envNames[0]))
	}
	return value
}

var bootstrapCmd = &cobra.Command{
	Use:                   "bootstrap",
	Short:                 "Used to bootstrap your Infisical instance",
	DisableFlagsInUseLine: true,
	Example:               "infisical bootstrap",
	Args:                  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		email := requiredBootstrapInput(cmd, "email", util.INFISICAL_BOOTSTRAP_EMAIL_NAME)
		password := requiredBootstrapInput(cmd, "password", util.INFISICAL_BOOTSTRAP_PASSWORD_NAME)
		organization := requiredBootstrapInput(cmd, "organization", util.INFISICAL_BOOTSTRAP_ORGANIZATION_NAME)
		domain := requiredBootstrapInput(cmd, "domain", util.DomainEnvNames...)

		setupToken, err := util.GetCmdFlagOrEnvWithDefaultValue(cmd, "setup-token", []string{util.INFISICAL_BOOTSTRAP_SETUP_TOKEN_NAME}, "")
		if err != nil {
			util.HandleError(err, "Unable to parse flag --setup-token")
		}

		outputType, err := cmd.Flags().GetString("output")
		if err != nil {
			util.HandleError(err, "Unable to parse flag --output")
		}

		k8SecretTemplate, err := cmd.Flags().GetString("k8-secret-template")
		if err != nil {
			util.HandleError(err, "Unable to parse flag --k8-secret-template")
		}

		k8SecretName, err := cmd.Flags().GetString("k8-secret-name")
		if err != nil {
			util.HandleError(err, "Unable to parse flag --k8-secret-name")
		}

		k8SecretNamespace, err := cmd.Flags().GetString("k8-secret-namespace")
		if err != nil {
			util.HandleError(err, "Unable to parse flag --k8-secret-namespace")
		}

		if outputType == "k8-secret" {
			if k8SecretTemplate == "" {
				util.PrintErrorMessageAndExit("k8-secret-template is required when using k8-secret output type")
			}

			if k8SecretName == "" {
				util.PrintErrorMessageAndExit("k8-secret-name is required when using k8-secret output type")
			}

			if k8SecretNamespace == "" {
				util.PrintErrorMessageAndExit("k8-secret-namespace is required when using k8-secret output type")
			}
		}

		httpClient, err := util.GetRestyClientWithCustomHeaders()
		if err != nil {
			util.HandleError(err, "Unable to create the HTTP client")
		}

		ignoreIfBootstrapped, err := cmd.Flags().GetBool("ignore-if-bootstrapped")
		if err != nil {
			util.HandleError(err, "Unable to parse flag --ignore-if-bootstrapped")
		}

		httpClient.SetHeader("Accept", "application/json")

		bootstrapResponse, err := api.CallBootstrapInstance(httpClient, api.BootstrapInstanceRequest{
			Domain:       util.AppendAPIEndpoint(domain),
			Email:        email,
			Password:     password,
			Organization: organization,
			SetupToken:   setupToken,
		})

		if err != nil {
			if ignoreIfBootstrapped && isInstanceAlreadySetUp(err) {
				return
			}
			util.HandleError(err, "Failed to bootstrap instance")
		}

		if outputType == "k8-secret" {
			if err := handleK8SecretOutput(bootstrapResponse, k8SecretTemplate, k8SecretName, k8SecretNamespace); err != nil {
				util.HandleError(err, "Failed to handle k8-secret output")
			}
		} else {
			responseJSON, err := json.MarshalIndent(bootstrapResponse, "", "  ")
			if err != nil {
				util.HandleError(err, "Failed to convert response to JSON")
			}

			util.PrintlnStdout(string(responseJSON))
		}
	},
}

func init() {
	bootstrapCmd.Flags().String("domain", "", "The domain of your self-hosted Infisical instance")
	bootstrapCmd.Flags().String("email", "", "The desired email address of the instance admin")
	bootstrapCmd.Flags().String("password", "", "The desired password of the instance admin")
	bootstrapCmd.Flags().String("organization", "", "The name of the organization to create for the instance")
	bootstrapCmd.Flags().String("output", "", "The type of output to use for the bootstrap command (json or k8-secret)")
	bootstrapCmd.Flags().Bool("ignore-if-bootstrapped", false, "Whether to continue on error if the instance has already been bootstrapped")
	bootstrapCmd.Flags().String("setup-token", "", "The instance setup token, required when the instance sets INSTANCE_SETUP_TOKEN")
	bootstrapCmd.Flags().String("k8-secret-template", "{\"data\":{\"token\":\"{{.Identity.Credentials.Token}}\"}}", "The template to use for rendering the Kubernetes secret (entire secret JSON)")
	bootstrapCmd.Flags().String("k8-secret-namespace", "", "The namespace to create the Kubernetes secret in")
	bootstrapCmd.Flags().String("k8-secret-name", "", "The name of the Kubernetes secret to create")
	RootCmd.AddCommand(bootstrapCmd)
}
