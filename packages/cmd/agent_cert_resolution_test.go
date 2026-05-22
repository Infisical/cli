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

func newApplicationServer(t *testing.T, applicationName, applicationID string, profiles []api.PkiApplicationProfile) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/cert-manager/applications/by-name/" + applicationName:
				_ = json.NewEncoder(w).Encode(api.GetPkiApplicationResponse{
					Application: api.PkiApplication{ID: applicationID, Name: applicationName},
				})
			case "/v1/cert-manager/applications/" + applicationID + "/profiles":
				_ = json.NewEncoder(w).Encode(api.ListPkiApplicationProfilesResponse{Profiles: profiles})
			default:
				http.NotFound(w, r)
			}
		}),
	)
	return server
}

func withMockInfisicalURL(t *testing.T, url string) {
	t.Helper()
	orig := config.INFISICAL_URL
	config.INFISICAL_URL = url
	t.Cleanup(func() { config.INFISICAL_URL = orig })
}

func TestResolveCertificateNameReferences_AttachedProfile(t *testing.T) {
	const (
		applicationName = "my-app"
		applicationID   = "app-uuid-1"
		profileSlug     = "crdb"
		profileID       = "profile-uuid-1"
	)

	server := newApplicationServer(t, applicationName, applicationID, []api.PkiApplicationProfile{
		{
			ApplicationID: applicationID,
			ProfileID:     profileID,
			ProfileSlug:   profileSlug,
		},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ApplicationName: applicationName, ProfileName: profileSlug},
	}

	require.NoError(t, resolveCertificateNameReferences(AgentConfigVersionV2, &certs, resty.New()))
	assert.Equal(t, applicationID, certs[0].ApplicationID)
	assert.Equal(t, profileID, certs[0].ProfileID)
}

func TestResolveCertificateNameReferences_ProfileNotAttached(t *testing.T) {
	const (
		applicationName = "my-app"
		applicationID   = "app-uuid-3"
	)

	server := newApplicationServer(t, applicationName, applicationID, []api.PkiApplicationProfile{
		{ApplicationID: applicationID, ProfileID: "x", ProfileSlug: "other-profile"},
	})
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ApplicationName: applicationName, ProfileName: "missing-profile"},
	}

	err := resolveCertificateNameReferences(AgentConfigVersionV2, &certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not attached")
}

func TestResolveCertificateNameReferences_MissingFieldsV2(t *testing.T) {
	certs := []AgentCertificateConfig{{}}
	err := resolveCertificateNameReferences(AgentConfigVersionV2, &certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "application-name")
}

func TestResolveCertificateNameReferences_UnsupportedVersion(t *testing.T) {
	certs := []AgentCertificateConfig{{ApplicationName: "a", ProfileName: "p"}}
	err := resolveCertificateNameReferences("v99", &certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func newLegacyServer(t *testing.T, projectSlug, projectID, profileSlug, profileID string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/projects/slug/" + projectSlug:
				_ = json.NewEncoder(w).Encode(api.GetProjectBySlugResponse{ID: projectID, Slug: projectSlug})
			case "/v1/cert-manager/certificate-profiles/slug/" + profileSlug:
				if r.URL.Query().Get("projectId") != projectID {
					http.Error(w, "wrong projectId", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(api.GetCertificateProfileResponse{
					CertificateProfile: api.CertificateProfile{ID: profileID, Slug: profileSlug, ProjectID: projectID},
				})
			default:
				http.NotFound(w, r)
			}
		}),
	)
	return server
}

func TestResolveCertificateNameReferences_LegacyProjectAndProfile(t *testing.T) {
	const (
		projectSlug = "my-project"
		projectID   = "project-uuid-legacy"
		profileSlug = "legacy-profile"
		profileID   = "profile-uuid-legacy"
	)

	server := newLegacyServer(t, projectSlug, projectID, profileSlug, profileID)
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ProjectName: projectSlug, ProfileName: profileSlug},
	}

	require.NoError(t, resolveCertificateNameReferences(AgentConfigVersionV1, &certs, resty.New()))
	assert.Equal(t, profileID, certs[0].ProfileID)
	assert.Empty(t, certs[0].ApplicationID, "application-id should remain empty when no application-name supplied")
}

func TestResolveCertificateNameReferences_LegacyProjectMissingProfile(t *testing.T) {
	const (
		projectSlug = "my-project"
		projectID   = "project-uuid-legacy"
	)

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/v1/projects/slug/"+projectSlug {
				_ = json.NewEncoder(w).Encode(api.GetProjectBySlugResponse{ID: projectID, Slug: projectSlug})
				return
			}
			http.NotFound(w, r)
		}),
	)
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ProjectName: projectSlug, ProfileName: "missing-profile"},
	}

	err := resolveCertificateNameReferences(AgentConfigVersionV1, &certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-profile")
	assert.Contains(t, err.Error(), projectSlug)
}

func TestResolveCertificateNameReferences_LegacyProjectNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ProjectName: "missing-project", ProfileName: "any-profile"},
	}

	err := resolveCertificateNameReferences(AgentConfigVersionV1, &certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-project")
}

func TestValidateCertificateSourceConfig_V1Accepted(t *testing.T) {
	certs := []AgentCertificateConfig{
		{ProjectName: "proj", ProfileName: "p"},
		{CertificateID: "00000000-0000-0000-0000-000000000000"},
	}
	require.NoError(t, validateCertificateSourceConfig(AgentConfigVersionV1, &certs))
}

func TestValidateCertificateSourceConfig_V1RejectsApplicationName(t *testing.T) {
	certs := []AgentCertificateConfig{
		{ProjectName: "proj", ProfileName: "p", ApplicationName: "app"},
	}
	err := validateCertificateSourceConfig(AgentConfigVersionV1, &certs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v1")
	assert.Contains(t, err.Error(), "application-name")
}

func TestValidateCertificateSourceConfig_V2Accepted(t *testing.T) {
	certs := []AgentCertificateConfig{
		{ApplicationName: "app", ProfileName: "p"},
		{CertificateID: "00000000-0000-0000-0000-000000000000"},
	}
	require.NoError(t, validateCertificateSourceConfig(AgentConfigVersionV2, &certs))
}

func TestValidateCertificateSourceConfig_V1MissingProfile(t *testing.T) {
	certs := []AgentCertificateConfig{{ProjectName: "proj"}}
	err := validateCertificateSourceConfig(AgentConfigVersionV1, &certs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v1")
	assert.Contains(t, err.Error(), "profile-name")
}

func TestValidateCertificateSourceConfig_V1MissingProject(t *testing.T) {
	certs := []AgentCertificateConfig{{ApplicationName: "app", ProfileName: "p"}}
	err := validateCertificateSourceConfig(AgentConfigVersionV1, &certs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v1")
	assert.Contains(t, err.Error(), "project-slug")
}

func TestValidateCertificateSourceConfig_V2RejectsProjectSlug(t *testing.T) {
	certs := []AgentCertificateConfig{{ProjectName: "proj", ProfileName: "p"}}
	err := validateCertificateSourceConfig(AgentConfigVersionV2, &certs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v2")
	assert.Contains(t, err.Error(), "project-slug")
}

func TestValidateCertificateSourceConfig_V2MissingApplication(t *testing.T) {
	certs := []AgentCertificateConfig{{ProfileName: "p"}}
	err := validateCertificateSourceConfig(AgentConfigVersionV2, &certs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v2")
	assert.Contains(t, err.Error(), "application-name")
}

func TestValidateCertificateSourceConfig_CertIDExclusivity(t *testing.T) {
	cases := []struct {
		name    string
		version string
		cert    AgentCertificateConfig
		message string
	}{
		{
			name:    "v1 with project-slug",
			version: AgentConfigVersionV1,
			cert:    AgentCertificateConfig{CertificateID: "00000000-0000-0000-0000-000000000000", ProjectName: "proj"},
			message: "project-slug",
		},
		{
			name:    "v2 with application-name",
			version: AgentConfigVersionV2,
			cert:    AgentCertificateConfig{CertificateID: "00000000-0000-0000-0000-000000000000", ApplicationName: "app"},
			message: "application-name",
		},
		{
			name:    "v1 with profile-name",
			version: AgentConfigVersionV1,
			cert:    AgentCertificateConfig{CertificateID: "00000000-0000-0000-0000-000000000000", ProfileName: "p"},
			message: "profile-name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs := []AgentCertificateConfig{tc.cert}
			err := validateCertificateSourceConfig(tc.version, &certs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

func TestValidateCertificateSourceConfig_UnsupportedVersion(t *testing.T) {
	certs := []AgentCertificateConfig{{ApplicationName: "app", ProfileName: "p"}}
	err := validateCertificateSourceConfig("v99", &certs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestResolveCertificateNameReferences_ApplicationNotFound(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}),
	)
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ApplicationName: "missing-app", ProfileName: "any-profile"},
	}

	err := resolveCertificateNameReferences(AgentConfigVersionV2, &certs, resty.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-app")
	assert.Contains(t, err.Error(), "failed to resolve application")
}

func TestResolveCertificateNameReferences_CertificateIDSkipsResolution(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("no API call expected for cert-id-only config; got %s", r.URL.Path)
			http.NotFound(w, r)
		}),
	)
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{CertificateID: "00000000-0000-0000-0000-000000000000"},
	}

	require.NoError(t, resolveCertificateNameReferences(AgentConfigVersionV2, &certs, resty.New()))
	assert.Empty(t, certs[0].ApplicationID)
	assert.Empty(t, certs[0].ProfileID)
}

func TestResolveCertificateNameReferences_MultipleCerts(t *testing.T) {
	const (
		appAName = "app-a"
		appAID   = "app-a-uuid"
		appBName = "app-b"
		appBID   = "app-b-uuid"
	)

	appAProfiles := []api.PkiApplicationProfile{
		{ApplicationID: appAID, ProfileID: "profile-a1", ProfileSlug: "a1"},
		{ApplicationID: appAID, ProfileID: "profile-a2", ProfileSlug: "a2"},
	}
	appBProfiles := []api.PkiApplicationProfile{
		{ApplicationID: appBID, ProfileID: "profile-b1", ProfileSlug: "b1"},
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/cert-manager/applications/by-name/" + appAName:
				_ = json.NewEncoder(w).Encode(api.GetPkiApplicationResponse{
					Application: api.PkiApplication{ID: appAID, Name: appAName},
				})
			case "/v1/cert-manager/applications/by-name/" + appBName:
				_ = json.NewEncoder(w).Encode(api.GetPkiApplicationResponse{
					Application: api.PkiApplication{ID: appBID, Name: appBName},
				})
			case "/v1/cert-manager/applications/" + appAID + "/profiles":
				_ = json.NewEncoder(w).Encode(api.ListPkiApplicationProfilesResponse{Profiles: appAProfiles})
			case "/v1/cert-manager/applications/" + appBID + "/profiles":
				_ = json.NewEncoder(w).Encode(api.ListPkiApplicationProfilesResponse{Profiles: appBProfiles})
			default:
				http.NotFound(w, r)
			}
		}),
	)
	t.Cleanup(server.Close)
	withMockInfisicalURL(t, server.URL)

	certs := []AgentCertificateConfig{
		{ApplicationName: appAName, ProfileName: "a1"},
		{ApplicationName: appAName, ProfileName: "a2"},
		{ApplicationName: appBName, ProfileName: "b1"},
		{CertificateID: "11111111-1111-1111-1111-111111111111"},
	}

	require.NoError(t, resolveCertificateNameReferences(AgentConfigVersionV2, &certs, resty.New()))

	assert.Equal(t, appAID, certs[0].ApplicationID)
	assert.Equal(t, "profile-a1", certs[0].ProfileID)
	assert.Equal(t, appAID, certs[1].ApplicationID)
	assert.Equal(t, "profile-a2", certs[1].ProfileID)
	assert.Equal(t, appBID, certs[2].ApplicationID)
	assert.Equal(t, "profile-b1", certs[2].ProfileID)
	assert.Empty(t, certs[3].ApplicationID)
	assert.Empty(t, certs[3].ProfileID)
}

