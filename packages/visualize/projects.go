package visualize

import "github.com/Infisical/infisical-merge/packages/api"

func PrintAllProjectsDetails(projects []api.ProjectDetails) {
	rows := [][3]string{}
	for _, project := range projects {
		rows = append(rows, [...]string{project.Name, project.Slug, project.ID})
	}

	headers := [...]string{"PROJECT NAME", "PROJECT SLUG", "PROJECT ID"}

	Table(headers, rows)
}

func PrintProjectEnvironments(project api.ProjectDetails) {
	rows := [][3]string{}
	for _, environment := range project.Environments {
		rows = append(rows, [...]string{environment.Name, environment.Slug, environment.ID})
	}

	headers := [...]string{"ENVIRONMENT NAME", "ENVIRONMENT SLUG", "ENVIRONMENT ID"}

	Table(headers, rows)
}
