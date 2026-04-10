package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/Infisical/infisical-merge/packages/api"
	"github.com/Infisical/infisical-merge/packages/config"
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

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/v1/projects/slug/"+projectSlug:
				json.NewEncoder(w).Encode(api.Project{
					ID:   projectID,
					Name: "My Project",
					Slug: projectSlug,
				})
			case r.URL.Path == "/v1/cert-manager/certificate-profiles/slug/"+profileSlug:
				require.Equal(t, projectID, r.URL.Query().Get("projectId"))
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

	httpClient := resty.New()
	err := resolveCertificateNameReferences(&certs, httpClient)
	require.NoError(t, err)
	assert.Equal(t, profileID, certs[0].ProfileID)
}

func TestSlugResolutionCompletesBeforeIssuance(t *testing.T) {
	const (
		projectSlug    = "infra-z-c-pk"
		projectID      = "proj-uuid-aaaa"
		profileSlug    = "crdb"
		profileID      = "profile-uuid-bbbb"
		slugDelay      = 200 * time.Millisecond
	)

	var (
		mu              sync.Mutex
		requestOrder    []string
		slugResolved    atomic.Bool
	)

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			requestOrder = append(requestOrder, r.Method+" "+r.URL.Path)
			mu.Unlock()

			switch {
			case r.URL.Path == "/v1/projects/slug/"+projectSlug:
				json.NewEncoder(w).Encode(api.Project{
					ID:   projectID,
					Name: "Infra Project",
					Slug: projectSlug,
				})

			case r.URL.Path == "/v1/cert-manager/certificate-profiles/slug/"+profileSlug:
				time.Sleep(slugDelay)
				slugResolved.Store(true)
				json.NewEncoder(w).Encode(api.GetCertificateProfileResponse{
					CertificateProfile: api.CertificateProfile{
						ID:        profileID,
						Name:      profileSlug,
						ProjectID: projectID,
					},
				})

			case r.URL.Path == "/v1/cert-manager/certificates":
				assert.True(t, slugResolved.Load(),
					"cert issuance POST fired before slug resolution completed")

				var req api.IssueCertificateRequest
				json.NewDecoder(r.Body).Decode(&req)
				assert.Equal(t, profileID, req.ProfileID,
					"profileId should be the resolved UUID, not the slug")

				json.NewEncoder(w).Encode(api.CertificateResponse{
					Certificate: &api.CertificateData{
						CertificateID: "cert-id-1",
						SerialNumber:  "serial-1",
						Certificate:   "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
						PrivateKey:    "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
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
		{
			ProjectName: projectSlug,
			ProfileName: profileSlug,
			Attributes: &CertificateAttributes{
				CommonName: "node",
				TTL:        "2160h",
			},
		},
	}

	httpClient := resty.New()

	err := resolveCertificateNameReferences(&certs, httpClient)
	require.NoError(t, err)
	require.Equal(t, profileID, certs[0].ProfileID,
		"ProfileID must be set after resolution")

	request := api.IssueCertificateRequest{
		ProfileID: certs[0].ProfileID,
	}
	if certs[0].Attributes != nil {
		request.Attributes = &api.CertificateAttributes{
			CommonName: certs[0].Attributes.CommonName,
			TTL:        certs[0].Attributes.TTL,
		}
	}

	resp, err := api.CallIssueCertificate(httpClient, request)
	require.NoError(t, err)
	require.NotNil(t, resp.Certificate)

	mu.Lock()
	order := make([]string, len(requestOrder))
	copy(order, requestOrder)
	mu.Unlock()

	require.GreaterOrEqual(t, len(order), 3,
		"expected at least 3 requests (project slug, profile slug, issue cert)")

	var profileIdx, issueIdx int
	for i, req := range order {
		if req == "GET /v1/cert-manager/certificate-profiles/slug/"+profileSlug {
			profileIdx = i
		}
		if req == "POST /v1/cert-manager/certificates" {
			issueIdx = i
		}
	}
	assert.Less(t, profileIdx, issueIdx,
		"profile slug resolution must complete before certificate issuance")
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
			switch {
			case r.URL.Path == "/v1/projects/slug/"+projectSlug:
				json.NewEncoder(w).Encode(api.Project{
					ID:   projectID,
					Name: "Multi Project",
					Slug: projectSlug,
				})
			default:
				for slug, id := range profiles {
					path := "/v1/cert-manager/certificate-profiles/slug/" + slug
					if r.URL.Path == path {
						json.NewEncoder(w).Encode(
							api.GetCertificateProfileResponse{
								CertificateProfile: api.CertificateProfile{
									ID:        id,
									Name:      slug,
									ProjectID: projectID,
								},
							},
						)
						return
					}
				}
				http.NotFound(w, r)
			}
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

	httpClient := resty.New()
	err := resolveCertificateNameReferences(&certs, httpClient)
	require.NoError(t, err)

	for i, cert := range certs {
		expected := profiles[cert.ProfileName]
		assert.Equal(t, expected, cert.ProfileID,
			"cert[%d] ProfileID mismatch", i)
	}
}
