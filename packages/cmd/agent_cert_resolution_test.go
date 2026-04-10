package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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
				assert.Equal(t, projectID, r.URL.Query().Get("projectId"))
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

// TestConcurrentIssuanceBlocksOnSlugResolution simulates the race
// condition that existed before the fix: slug resolution and certificate
// issuance starting concurrently. The mock server delays the slug
// resolution response by 200ms. A goroutine fires the issuance POST
// immediately (mimicking the old MonitorCertificates goroutine). The
// server rejects any issuance POST that arrives before slug resolution
// has completed, proving the ordering guarantee matters.
func TestConcurrentIssuanceBlocksOnSlugResolution(t *testing.T) {
	const (
		projectSlug = "infra-z-c-pk"
		projectID   = "proj-uuid-aaaa"
		profileSlug = "crdb"
		profileID   = "profile-uuid-bbbb"
		slugDelay   = 200 * time.Millisecond
	)

	var slugResolved atomic.Bool
	var issuanceReceivedBeforeResolution atomic.Bool

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

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
				if !slugResolved.Load() {
					issuanceReceivedBeforeResolution.Store(true)
					w.WriteHeader(http.StatusUnprocessableEntity)
					json.NewEncoder(w).Encode(map[string]string{
						"message": "Invalid uuid",
					})
					return
				}
				var req api.IssueCertificateRequest
				json.NewDecoder(r.Body).Decode(&req)
				if req.ProfileID != profileID {
					w.WriteHeader(http.StatusUnprocessableEntity)
					json.NewEncoder(w).Encode(map[string]string{
						"message": "Invalid uuid",
					})
					return
				}
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

	// Simulate the fixed code path: resolve first, then issue.
	// This mirrors the merged goroutine in certManagerAgentCmd.
	err := resolveCertificateNameReferences(&certs, httpClient)
	require.NoError(t, err)
	require.Equal(t, profileID, certs[0].ProfileID)

	request := api.IssueCertificateRequest{
		ProfileID: certs[0].ProfileID,
		Attributes: &api.CertificateAttributes{
			CommonName: "node",
			TTL:        "2160h",
		},
	}
	resp, err := api.CallIssueCertificate(httpClient, request)
	require.NoError(t, err)
	require.NotNil(t, resp.Certificate)

	assert.False(t, issuanceReceivedBeforeResolution.Load(),
		"issuance POST must not arrive before slug resolution completes")

	// Now simulate the OLD buggy code path: fire issuance concurrently
	// with resolution. The server should reject it because slug
	// resolution hasn't completed when the POST arrives.
	slugResolved.Store(false)
	issuanceReceivedBeforeResolution.Store(false)

	unresolvedCerts := []AgentCertificateConfig{
		{
			ProjectName: projectSlug,
			ProfileName: profileSlug,
			Attributes: &CertificateAttributes{
				CommonName: "node",
				TTL:        "2160h",
			},
		},
	}

	earlyIssuanceFailed := make(chan bool, 1)

	// Goroutine 1: start resolving (takes 200ms due to server delay)
	go func() {
		resolveClient := resty.New()
		resolveCertificateNameReferences(&unresolvedCerts, resolveClient)
	}()

	// Goroutine 2: fire issuance immediately with unresolved slug
	// (ProfileID is still empty — mimics old MonitorCertificates)
	go func() {
		issueClient := resty.New()
		earlyReq := api.IssueCertificateRequest{
			ProfileID: unresolvedCerts[0].ProfileID,
			Attributes: &api.CertificateAttributes{
				CommonName: "node",
				TTL:        "2160h",
			},
		}
		_, err := api.CallIssueCertificate(issueClient, earlyReq)
		earlyIssuanceFailed <- (err != nil)
	}()

	failed := <-earlyIssuanceFailed
	assert.True(t, failed,
		"issuance with unresolved ProfileID should fail (422)")
	assert.True(t, issuanceReceivedBeforeResolution.Load(),
		"server should have seen the issuance POST before slug resolution finished")
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
