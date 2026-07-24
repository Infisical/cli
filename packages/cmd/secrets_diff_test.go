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
