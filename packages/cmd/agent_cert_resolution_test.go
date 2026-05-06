package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveCertificateNameReferences(t *testing.T) {
	const (
		projectSlug = "my-project"
		projectID   = "proj-uuid-1234"
		profileSlug = "crdb"
		profileID   = "profile-uuid-5678"
	)

	var gotProjectIDQuery string

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/projects/slug/" + projectSlug:
				json.NewEncoder(w).Encode(api.Project{
					ID:   projectID,
					Name: "My Project",
					Slug: projectSlug,
				})
			case "/v1/cert-manager/certificate-profiles/slug/" + profileSlug:
				gotProjectIDQuery = r.URL.Query().Get("projectId")
				json.NewEncoder(w).Encode(api.GetCertificateProfileResponse{
					CertificateProfile: api.CertificateProfile{
						ID:        profileID,
						Name:      profileSlug,
						ProjectID: projectID,
					},
				})
			default:
				http.NotFound(w, r)
			}
		}),
	)
	t.Cleanup(server.Close)

	orig := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = orig })

	certs := []AgentCertificateConfig{
		{ProjectName: projectSlug, ProfileName: profileSlug},
	}

	require.NoError(t, resolveCertificateNameReferences(&certs, resty.New()))
	assert.Equal(t, profileID, certs[0].ProfileID)
	assert.Equal(t, projectID, gotProjectIDQuery, "profile lookup must pass resolved projectId query param")
}

func TestResolveCertificateNameReferences_MultipleProfiles(t *testing.T) {
	const (
		projectSlug = "multi-project"
		projectID   = "proj-uuid-multi"
	)

	profiles := map[string]string{
		"profile-a": "uuid-aaaa",
		"profile-b": "uuid-bbbb",
		"profile-c": "uuid-cccc",
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/v1/projects/slug/"+projectSlug {
				json.NewEncoder(w).Encode(api.Project{
					ID:   projectID,
					Name: "Multi Project",
					Slug: projectSlug,
				})
				return
			}
			for slug, id := range profiles {
				if r.URL.Path == "/v1/cert-manager/certificate-profiles/slug/"+slug {
					json.NewEncoder(w).Encode(api.GetCertificateProfileResponse{
						CertificateProfile: api.CertificateProfile{
							ID:        id,
							Name:      slug,
							ProjectID: projectID,
						},
					})
					return
				}
			}
			http.NotFound(w, r)
		}),
	)
	t.Cleanup(server.Close)

	orig := config.INFISICAL_URL
	config.INFISICAL_URL = server.URL
	t.Cleanup(func() { config.INFISICAL_URL = orig })

	certs := []AgentCertificateConfig{
		{ProjectName: projectSlug, ProfileName: "profile-a"},
		{ProjectName: projectSlug, ProfileName: "profile-b"},
		{ProjectName: projectSlug, ProfileName: "profile-c"},
	}

	require.NoError(t, resolveCertificateNameReferences(&certs, resty.New()))

	for i, cert := range certs {
		assert.Equal(t, profiles[cert.ProfileName], cert.ProfileID, "cert[%d] ProfileID mismatch", i)
	}
}

func TestResolveCertificateNameReferences_MissingSlugs(t *testing.T) {
	certs := []AgentCertificateConfig{{}}
	err := resolveCertificateNameReferences(&certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project-slug")
}
