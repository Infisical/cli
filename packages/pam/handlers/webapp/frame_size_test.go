package webapp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/jpeg"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

func TestOversizedFrameIsReencodedAndRecorded(t *testing.T) {
	s, recording, _ := supervisorFixture(t)
	dialogCDP(t, s, false)
	source := image.NewRGBA(image.Rect(0, 0, 1920, 1200))
	random := rand.New(rand.NewPCG(1, 2))
	for i := range source.Pix {
		source.Pix[i] = byte(random.Uint32())
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, source, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() <= 1<<20 {
		t.Fatal("fixture JPEG did not exercise oversized capture")
	}
	if err := s.storeFrame("page", base64.StdEncoding.EncodeToString(encoded.Bytes()), true); err != nil {
		t.Fatal(err)
	}
	recording.mu.Lock()
	defer recording.mu.Unlock()
	health, frames := 0, 0
	for _, event := range recording.events {
		if event["type"] == "health" && event["detail"] == "frame re-encoded for recording event limit" {
			health++
		}
		if event["type"] != "frame" {
			continue
		}
		frames++
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := json.Marshal(session.SessionEvent{Timestamp: time.Now(), EventType: session.SessionEventWeb, ChannelType: session.SessionChannelWeb, Data: data, ElapsedTime: time.Since(s.started).Seconds()})
		if err != nil {
			t.Fatal(err)
		}
		if len(wrapped) > maxFrameEventBytes {
			t.Fatalf("serialized frame event exceeds cap: %d", len(wrapped))
		}
		imageBytes, err := base64.StdEncoding.DecodeString(event["jpeg"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jpeg.Decode(bytes.NewReader(imageBytes)); err != nil {
			t.Fatal(err)
		}
	}
	if frames != 1 || health != 1 {
		t.Fatalf("frame was silently dropped or not annotated: frames=%d health=%d", frames, health)
	}
	settings := s.surfaces[1].capture.Load()
	if settings == nil || settings.quality > 60 || settings.width > 1920 {
		t.Fatal("surface capture settings did not adapt")
	}
	if s.droppedCapture != 0 {
		t.Fatal("oversized frame counted as dropped")
	}
}
