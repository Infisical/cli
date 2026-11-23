package cmd

import (
	"testing"

	"github.com/Infisical/infisical-merge/packages/models"
)

func TestComputeSecretDiff_DetectsAddedRemovedChangedAndUnchanged(t *testing.T) {
	left := []models.SingleEnvironmentVariable{
		{Key: "SAME", Value: "same-value"},
		{Key: "CHANGED", Value: "old-value"},
		{Key: "ONLY_LEFT", Value: "left-only"},
	}
	right := []models.SingleEnvironmentVariable{
		{Key: "SAME", Value: "same-value"},
		{Key: "CHANGED", Value: "new-value"},
		{Key: "ONLY_RIGHT", Value: "right-only"},
	}

	diff := computeSecretDiff(left, right)

	if len(diff) != 3 {
		t.Fatalf("expected 3 diff entries (unchanged key excluded), got %d: %+v", len(diff), diff)
	}

	byKey := make(map[string]secretDiffEntry, len(diff))
	for _, entry := range diff {
		byKey[entry.Key] = entry
	}

	if _, ok := byKey["SAME"]; ok {
		t.Errorf("expected unchanged key SAME to be excluded from diff")
	}

	changed, ok := byKey["CHANGED"]
	if !ok {
		t.Fatalf("expected CHANGED key in diff")
	}
	if changed.Status != secretDiffStatusChanged {
		t.Errorf("expected CHANGED status, got %s", changed.Status)
	}
	if changed.LeftValue != "old-value" || changed.RightValue != "new-value" {
		t.Errorf("unexpected values for CHANGED: %+v", changed)
	}

	onlyLeft, ok := byKey["ONLY_LEFT"]
	if !ok {
		t.Fatalf("expected ONLY_LEFT key in diff")
	}
	if onlyLeft.Status != secretDiffStatusRemoved {
		t.Errorf("expected removed status for ONLY_LEFT, got %s", onlyLeft.Status)
	}

	onlyRight, ok := byKey["ONLY_RIGHT"]
	if !ok {
		t.Fatalf("expected ONLY_RIGHT key in diff")
	}
	if onlyRight.Status != secretDiffStatusAdded {
		t.Errorf("expected added status for ONLY_RIGHT, got %s", onlyRight.Status)
	}
}

func TestComputeSecretDiff_EmptyWhenIdentical(t *testing.T) {
	secrets := []models.SingleEnvironmentVariable{
		{Key: "A", Value: "1"},
		{Key: "B", Value: "2"},
	}

	diff := computeSecretDiff(secrets, secrets)

	if len(diff) != 0 {
		t.Errorf("expected no diff entries for identical secret sets, got %d: %+v", len(diff), diff)
	}
}

func TestComputeSecretDiff_ResultsSortedByKey(t *testing.T) {
	left := []models.SingleEnvironmentVariable{}
	right := []models.SingleEnvironmentVariable{
		{Key: "ZEBRA", Value: "z"},
		{Key: "ALPHA", Value: "a"},
		{Key: "MID", Value: "m"},
	}

	diff := computeSecretDiff(left, right)

	if len(diff) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(diff))
	}
	want := []string{"ALPHA", "MID", "ZEBRA"}
	for i, key := range want {
		if diff[i].Key != key {
			t.Errorf("expected sorted key %q at index %d, got %q", key, i, diff[i].Key)
		}
	}
}

func TestMaskDiffValue_MasksNonEmptySide(t *testing.T) {
	if got := maskDiffValue(secretDiffStatusChanged, secretDiffStatusRemoved, "secret"); got != "******" {
		t.Errorf("expected masked value for changed status, got %q", got)
	}
}

func TestMaskDiffValue_LeavesEmptyForMissingSide(t *testing.T) {
	if got := maskDiffValue(secretDiffStatusRemoved, secretDiffStatusRemoved, "secret"); got != "" {
		t.Errorf("expected empty value when status matches emptyWhenStatus, got %q", got)
	}
}

func TestMaskDiffColumns_RemovedShowsMaskedLeftAndEmptyRight(t *testing.T) {
	left, right := maskDiffColumns(secretDiffStatusRemoved, "left-secret", "")
	if left != "******" {
		t.Errorf("expected masked left for removed key, got %q", left)
	}
	if right != "" {
		t.Errorf("expected empty right for removed key, got %q", right)
	}
}

func TestMaskDiffColumns_AddedShowsEmptyLeftAndMaskedRight(t *testing.T) {
	left, right := maskDiffColumns(secretDiffStatusAdded, "", "right-secret")
	if left != "" {
		t.Errorf("expected empty left for added key, got %q", left)
	}
	if right != "******" {
		t.Errorf("expected masked right for added key, got %q", right)
	}
}

func TestMaskDiffColumns_ChangedMasksBothSides(t *testing.T) {
	left, right := maskDiffColumns(secretDiffStatusChanged, "old", "new")
	if left != "******" || right != "******" {
		t.Errorf("expected both sides masked for changed key, got left=%q right=%q", left, right)
	}
}

func TestResolveDiffPath2_DefaultsToPath1(t *testing.T) {
	if got := resolveDiffPath2("/app", ""); got != "/app" {
		t.Errorf("expected path2 to default to path1, got %q", got)
	}
	if got := resolveDiffPath2("/app", "/db"); got != "/db" {
		t.Errorf("expected explicit path2 to be preserved, got %q", got)
	}
}

func TestValidateDiffTargets_AllowsSameEnvDifferentPath(t *testing.T) {
	if err := validateDiffTargets("staging", "staging", "/app", "/db"); err != nil {
		t.Errorf("expected same-env different-path comparison to be allowed, got %v", err)
	}
}

func TestValidateDiffTargets_RejectsIdenticalEnvAndPath(t *testing.T) {
	if err := validateDiffTargets("staging", "staging", "/app", "/app"); err == nil {
		t.Errorf("expected identical env+path comparison to be rejected")
	}
}

func TestValidateDiffTargets_AllowsDifferentEnvSamePath(t *testing.T) {
	if err := validateDiffTargets("staging", "production", "/app", "/app"); err != nil {
		t.Errorf("expected different-env same-path comparison to be allowed, got %v", err)
	}
}
