package util

import (
	"fmt"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/Infisical/infisical-merge/packages/models"
)

// OrgPickerItem pairs a display label with the org ID to pass to CallSelectOrganization.
type OrgPickerItem struct {
	ID    string
	Label string
}

// BuildOrgRootLabels returns first-prompt labels: org name with sub-org count when present.
// orgs is the flat list from GET /v1/organization; subOrgMap is keyed by org ID.
func BuildOrgRootLabels(orgs []api.Organization, subOrgMap map[string][]api.SubOrganization) []string {
	labels := make([]string, len(orgs))
	for i, org := range orgs {
		n := len(subOrgMap[org.ID])
		switch n {
		case 0:
			labels[i] = org.Name
		case 1:
			labels[i] = fmt.Sprintf("%s (1 sub-org)", org.Name)
		default:
			labels[i] = fmt.Sprintf("%s (%d sub-orgs)", org.Name, n)
		}
	}
	return labels
}

// BuildSubOrgPickerItems returns items + labels for the second prompt.
// The first item is always the root org itself, followed by each sub-org.
func BuildSubOrgPickerItems(rootID, rootName string, subs []api.SubOrganization) ([]OrgPickerItem, []string) {
	items := make([]OrgPickerItem, 0, 1+len(subs))
	labels := make([]string, 0, 1+len(subs))

	rootLabel := fmt.Sprintf("%s (organization)", rootName)
	items = append(items, OrgPickerItem{ID: rootID, Label: rootLabel})
	labels = append(labels, rootLabel)

	for _, sub := range subs {
		items = append(items, OrgPickerItem{ID: sub.ID, Label: sub.Name})
		labels = append(labels, sub.Name)
	}
	return items, labels
}

func GetWorkspacesInOrganization(workspaceResponse api.GetWorkSpacesResponse, orgId string) ([]models.Workspace, []string) {
	workspaces := workspaceResponse.Workspaces

	var filteredWorkspaces []models.Workspace
	var workspaceNames []string

	for _, workspace := range workspaces {
		if workspace.OrganizationId == orgId {
			filteredWorkspaces = append(filteredWorkspaces, workspace)
			workspaceNames = append(workspaceNames, workspace.Name)
		}
	}

	if len(filteredWorkspaces) == 0 {
		message := fmt.Sprintf("You don't have any projects created in Infisical organization. You must first create a project at %s", config.INFISICAL_URL)
		PrintErrorMessageAndExit(message)
	}

	return filteredWorkspaces, workspaceNames
}
