package webapp

import (
	"strings"
	"unicode/utf8"
)

func virtualKeyCode(code, key string) int {
	for _, value := range []string{code, key} {
		if len(value) == 4 && strings.HasPrefix(value, "Key") && value[3] >= 'A' && value[3] <= 'Z' {
			return int(value[3])
		}
		if len(value) == 6 && strings.HasPrefix(value, "Digit") && value[5] >= '0' && value[5] <= '9' {
			return int(value[5])
		}
		if len(value) == 1 {
			character := strings.ToUpper(value)[0]
			if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
				return int(character)
			}
		}
		if vk, ok := map[string]int{
			"Backspace": 8, "Tab": 9, "Enter": 13, "NumpadEnter": 13, "Shift": 16, "ShiftLeft": 16, "ShiftRight": 16, "Control": 17, "ControlLeft": 17, "ControlRight": 17, "Alt": 18, "AltLeft": 18, "AltRight": 18, "Escape": 27, "Space": 32, " ": 32, "PageUp": 33, "PageDown": 34, "End": 35, "Home": 36, "ArrowLeft": 37, "ArrowUp": 38, "ArrowRight": 39, "ArrowDown": 40, "Delete": 46, "Meta": 91, "MetaLeft": 91, "MetaRight": 92, "F1": 112, "F2": 113, "F3": 114, "F4": 115, "F5": 116, "F6": 117, "F7": 118, "F8": 119, "F9": 120, "F10": 121, "F11": 122, "F12": 123,
			"Semicolon": 186, ";": 186, ":": 186, "Equal": 187, "=": 187, "+": 187, "Comma": 188, ",": 188, "<": 188, "Minus": 189, "-": 189, "_": 189, "Period": 190, ".": 190, ">": 190, "Slash": 191, "/": 191, "?": 191, "Backquote": 192, "`": 192, "~": 192, "BracketLeft": 219, "[": 219, "{": 219, "Backslash": 220, "\\": 220, "|": 220, "BracketRight": 221, "]": 221, "}": 221, "Quote": 222, "'": 222, "\"": 222,
		}[value]; ok {
			return vk
		}
	}
	return 0
}

func keyEventParams(m message) (map[string]any, string) {
	code := virtualKeyCode(m.Code, m.Key)
	text := m.Text
	kind := "rawKeyDown"
	if m.Action == "up" {
		kind = "keyUp"
		text = ""
	} else {
		if code == 13 {
			text = "\r"
		} else if text == "" && utf8.RuneCountInString(m.Key) == 1 && m.Modifiers&7 == 0 {
			text = m.Key
		}
		if text != "" {
			kind = "keyDown"
		}
	}
	return map[string]any{"type": kind, "key": m.Key, "code": m.Code, "modifiers": m.Modifiers, "text": text, "unmodifiedText": text, "windowsVirtualKeyCode": code, "nativeVirtualKeyCode": code, "autoRepeat": false}, text
}
