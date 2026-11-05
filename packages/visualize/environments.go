package visualize

import (
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

func PrintEnvironmentDetails(environment api.Environment) {
	headers := [...]string{"ENVIRONMENT NAME", "ENVIRONMENT SLUG", "ENVIRONMENT ID"}
	rows := [][3]string{{util.SanitizeDisplay(environment.Name), util.SanitizeDisplay(environment.Slug), util.SanitizeDisplay(environment.ID)}}

	Table(headers, rows)
}
