package visualize

import (
	"strconv"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/util"
)

func PrintEnvironmentDetails(environment api.Environment) {
	GenericTable(
		[]string{"ENVIRONMENT NAME", "ENVIRONMENT SLUG", "POSITION", "ENVIRONMENT ID"},
		[][]string{{util.SanitizeDisplay(environment.Name), util.SanitizeDisplay(environment.Slug), strconv.Itoa(environment.Position), util.SanitizeDisplay(environment.ID)}},
	)
}
