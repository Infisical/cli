package webapp

import "testing"

func TestVirtualKeyMappingAndEventParams(t *testing.T) {
	for key, want := range map[string]int{"Backspace": 8, "Tab": 9, "Enter": 13, "ShiftLeft": 16, "ControlRight": 17, "AltLeft": 18, "Escape": 27, "Space": 32, "PageUp": 33, "PageDown": 34, "End": 35, "Home": 36, "ArrowLeft": 37, "ArrowUp": 38, "ArrowRight": 39, "ArrowDown": 40, "Delete": 46, "Digit0": 48, "Digit9": 57, "KeyA": 65, "KeyZ": 90, "F1": 112, "F12": 123, "Semicolon": 186, "Equal": 187, "Comma": 188, "Minus": 189, "Period": 190, "Slash": 191, "Backquote": 192, "BracketLeft": 219, "Backslash": 220, "BracketRight": 221, "Quote": 222} {
		for _, action := range []string{"down", "up"} {
			params, _ := keyEventParams(message{Action: action, Code: key, Key: key, Modifiers: 2})
			if params["windowsVirtualKeyCode"] != want || params["nativeVirtualKeyCode"] != want || params["modifiers"] != 2 || params["autoRepeat"] != false {
				t.Fatalf("%s %s: %+v", key, action, params)
			}
		}
	}
	if virtualKeyCode("Unidentified", "Backspace") != 8 || virtualKeyCode("", "z") != 90 {
		t.Fatal("key fallback mapping failed")
	}
	for _, tc := range []struct {
		m          message
		kind, text string
	}{
		{message{Action: "down", Code: "Backspace", Key: "Backspace"}, "rawKeyDown", ""},
		{message{Action: "down", Code: "Enter", Key: "Enter"}, "keyDown", "\r"},
		{message{Action: "up", Code: "Enter", Key: "Enter"}, "keyUp", ""},
		{message{Action: "down", Code: "KeyA", Key: "a"}, "keyDown", "a"},
		{message{Action: "down", Code: "KeyA", Key: "a", Modifiers: 2}, "rawKeyDown", ""},
		{message{Action: "down", Code: "Digit1", Key: "!", Text: "!", Modifiers: 8}, "keyDown", "!"},
	} {
		params, text := keyEventParams(tc.m)
		if params["type"] != tc.kind || text != tc.text || params["unmodifiedText"] != tc.text {
			t.Fatalf("wrong key event: %+v", params)
		}
	}
}
