package visualize

import (
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

func PrintAllProjectsDetails(projects []api.ProjectDetails) {
	rows := [][3]string{}
	for _, project := range projects {
		rows = append(rows, [...]string{util.SanitizeDisplay(project.Name), util.SanitizeDisplay(project.Slug), util.SanitizeDisplay(project.ID)})
	}

	headers := [...]string{"PROJECT NAME", "PROJECT SLUG", "PROJECT ID"}

	Table(headers, rows)
}

func PrintProjectEnvironments(project api.ProjectDetails) {
	rows := [][3]string{}
	for _, environment := range project.Environments {
		rows = append(rows, [...]string{util.SanitizeDisplay(environment.Name), util.SanitizeDisplay(environment.Slug), util.SanitizeDisplay(environment.ID)})
	}

	headers := [...]string{"ENVIRONMENT NAME", "ENVIRONMENT SLUG", "ENVIRONMENT ID"}

	Table(headers, rows)
}
