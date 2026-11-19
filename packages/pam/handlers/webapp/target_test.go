package webapp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/accessibility"
	"github.com/chromedp/cdproto/cdp"
)

func element(tag string, attrs []string, children ...*cdp.Node) *cdp.Node {
	return &cdp.Node{NodeType: 1, NodeName: strings.ToUpper(tag), LocalName: tag, Attributes: attrs, Children: children}
}

func text(value string) *cdp.Node {
	return &cdp.Node{NodeType: 3, NodeName: "#text", NodeValue: value}
}

func TestBuildTargetNeverRecordsFieldContents(t *testing.T) {
	cases := []struct {
		name string
		node *cdp.Node
		role string
	}{
		{"input", element("input", []string{"type", "text", "value", "typed secret"}), "textbox"},
		{"textarea", element("textarea", nil, text("typed secret")), "textbox"},
		{"select", element("select", nil, element("option", nil, text("typed secret"))), "combobox"},
		{"contenteditable", element("div", []string{"contenteditable", "true"}, text("typed secret")), "generic"},
		{"empty contenteditable", element("div", []string{"contenteditable", ""}, text("typed secret")), "generic"},
		{"role textbox", element("div", []string{"role", "textbox"}, text("typed secret")), "textbox"},
	}
	for _, tc := range cases {
		got := buildTarget(tc.node, tc.role, "Email")
		if got.Text != "" {
			t.Errorf("%s recorded text %q", tc.name, got.Text)
		}
		if got.Name != "Email" || got.Role != tc.role {
			t.Errorf("%s = %+v", tc.name, got)
		}
	}
}

func TestBuildTargetPasswordKeepsOnlyTagAndRole(t *testing.T) {
	got := buildTarget(element("INPUT", []string{"TYPE", "Password", "value", "hunter2"}), "textbox", "Password for alice")
	if got.Tag != "input" || got.Role != "textbox" || got.Name != "" || got.Text != "" {
		t.Errorf("password target = %+v", got)
	}
}

func TestBuildTargetTextOfOtherElements(t *testing.T) {
	long := strings.Repeat("word ", 40)
	link := element("a", []string{"href", "/x"},
		text("  Save\n "), element("span", nil, text("the   dashboard")), element("script", nil, text("var x = 1")))
	got := buildTarget(link, "link", "Save the dashboard")
	if got.Tag != "a" || got.Role != "link" || got.Name != "Save the dashboard" || got.Text != "Save the dashboard" {
		t.Errorf("link = %+v", got)
	}

	got = buildTarget(element("p", nil, text(long)), "paragraph", long)
	if n := len([]rune(got.Text)); n != maxTargetChars {
		t.Errorf("text length = %d, want %d", n, maxTargetChars)
	}
	if n := len([]rune(got.Name)); n != maxTargetChars {
		t.Errorf("name length = %d, want %d", n, maxTargetChars)
	}

	got = buildTarget(&cdp.Node{NodeType: 1, NodeName: "BUTTON"}, "button", "")
	if got.Tag != "button" {
		t.Errorf("tag from nodeName = %q", got.Tag)
	}
}

func TestTakesText(t *testing.T) {
	cases := []struct {
		node *cdp.Node
		role string
		want bool
	}{
		{element("input", nil), "textbox", true},
		{element("input", []string{"type", "search"}), "searchbox", true},
		{element("input", []string{"type", "password"}), "textbox", true},
		{element("input", []string{"type", "checkbox"}), "checkbox", false},
		{element("input", []string{"type", "submit"}), "button", false},
		{element("textarea", nil), "textbox", false},
		{element("div", []string{"contenteditable", "true"}), "textbox", true},
		{element("div", []string{"contenteditable", "false"}), "generic", false},
		{element("button", nil), "button", false},
		{element("body", nil), "", false},
	}
	for _, tc := range cases {
		if got := takesText(tc.node, tc.role); got != tc.want {
			t.Errorf("takesText(%s %v) = %v", tc.node.LocalName, tc.node.Attributes, got)
		}
	}
}

func axValue(s string) *accessibility.Value {
	raw, _ := json.Marshal(s)
	return &accessibility.Value{Type: accessibility.ValueTypeString, Value: raw}
}

func TestPickTargetNode(t *testing.T) {
	nodes := []*accessibility.Node{
		{NodeID: "1", Role: axValue("RootWebArea"), BackendDOMNodeID: 1},
		{NodeID: "2", ParentID: "1", Role: axValue("generic"), BackendDOMNodeID: 2},
		{NodeID: "3", ParentID: "2", Role: axValue("link"), Name: axValue("Next"), BackendDOMNodeID: 3},
		{NodeID: "4", ParentID: "3", Ignored: true, Role: axValue("none"), BackendDOMNodeID: 4},
		{NodeID: "5", ParentID: "4", Role: axValue("StaticText"), Name: axValue("Next"), BackendDOMNodeID: 5},
	}
	if got := pickTargetNode(nodes, 5); got == nil || got.BackendDOMNodeID != 3 {
		t.Errorf("text inside a link picked %+v", got)
	}

	plain := []*accessibility.Node{
		{NodeID: "1", Role: axValue("RootWebArea"), BackendDOMNodeID: 1},
		{NodeID: "2", ParentID: "1", Role: axValue("paragraph"), BackendDOMNodeID: 2},
		{NodeID: "3", ParentID: "2", Role: axValue("StaticText"), BackendDOMNodeID: 3},
	}
	if got := pickTargetNode(plain, 3); got == nil || got.BackendDOMNodeID != 2 {
		t.Errorf("plain text picked %+v", got)
	}

	cycle := []*accessibility.Node{
		{NodeID: "1", ParentID: "2", Ignored: true, BackendDOMNodeID: 1},
		{NodeID: "2", ParentID: "1", Ignored: true, BackendDOMNodeID: 2},
	}
	if got := pickTargetNode(cycle, 1); got != nil {
		t.Errorf("cycle picked %+v", got)
	}
	if got := pickTargetNode(nodes, 99); got != nil {
		t.Errorf("unknown node picked %+v", got)
	}
}
