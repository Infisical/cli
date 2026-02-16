package util

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/Infisical/infisical-merge/packages/templates"
	"github.com/rs/zerolog/log"
)

func WriteSystemdServiceFile(
	serviceLogFilePath string,
	environmentFilePath string,
	serviceName string, // service name (e.g. infisical-relay)
	serviceType string, // service type (e.g. relay, gateway)
	description string, // service description (e.g. Infisical Relay Service)
) error {

	data := map[string]string{
		"Description":     description,
		"EnvironmentFile": environmentFilePath,
		"ServiceType":     serviceType,
	}

	if serviceLogFilePath != "" {
		serviceLogFile := filepath.Clean(serviceLogFilePath)

		if !filepath.IsAbs(serviceLogFile) {
			return fmt.Errorf("log-file must be an absolute path: %s", serviceLogFile)
		}

		logDir := filepath.Dir(serviceLogFile)

		// create the directory structure with appropriate permissions
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory %s: %w", logDir, err)
		}

		// create the log file if it doesn't exist
		logFile, err := os.OpenFile(serviceLogFile, os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to create log file %s: %w", serviceLogFile, err)
		}
		logFile.Close()

		data["ServiceLogFile"] = serviceLogFile
	}

	tmpl, err := template.ParseFS(templates.TemplatesFS, "infisical-service.tmpl")
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if err := os.WriteFile(servicePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %v", err)
	}

	return nil

}

func WriteLogrotateFile(
	serviceLogFilePath string,
	serviceName string, // service name (e.g. infisical-relay)
) error {

	if serviceLogFilePath == "" {
		return nil
	}

	logrotateDirectory := "/etc/logrotate.d"

	// check if /etc/logrotate.d exists (logrotate.d is a directory )
	if _, err := os.Stat(logrotateDirectory); os.IsNotExist(err) {
		log.Warn().Msg("logrotate.d directory does not exist. log files will not be pruned automatically.")
	} else if err != nil {
		return fmt.Errorf("failed to check if logrotate.d directory exists: %v", err)
	} else {

		logrotateTmpl, err := template.ParseFS(templates.TemplatesFS, "logrotate.d.tmpl")
		if err != nil {
			return fmt.Errorf("failed to parse logrotate template: %v", err)
		}

		data := map[string]string{
			"LogFilePath": serviceLogFilePath,
			"ServiceName": serviceName,
		}

		var buf bytes.Buffer
		if err := logrotateTmpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("failed to execute logrotate template: %v", err)
		}

		if err := os.WriteFile(filepath.Join(logrotateDirectory, serviceName), buf.Bytes(), 0644); err != nil {
			return fmt.Errorf("failed to write logrotate file: %v", err)
		}
	}

	return nil

}
