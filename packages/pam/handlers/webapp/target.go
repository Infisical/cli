package webapp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/accessibility"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"

	"github.com/Infisical/infisical-merge/packages/pam/session"
)

const (
	maxTargetChars    = 80
	targetDOMDepth    = 3
	targetObjectGroup = "infisical-recorder"
)

var interactiveRoles = map[string]bool{
	"link": true, "button": true, "checkbox": true, "radio": true, "switch": true,
	"textbox": true, "searchbox": true, "combobox": true, "listbox": true, "option": true,
	"menuitem": true, "menuitemcheckbox": true, "menuitemradio": true, "tab": true,
	"slider": true, "spinbutton": true, "treeitem": true,
}

var fieldRoles = map[string]bool{"textbox": true, "searchbox": true, "combobox": true, "spinbutton": true}

var nonTextInputTypes = map[string]bool{
	"button": true, "submit": true, "reset": true, "image": true, "checkbox": true,
	"radio": true, "file": true, "range": true, "color": true, "hidden": true,
}

// targetDescriber names the elements that input lands on. It reads them only through the DOM and
// accessibility domains and an isolated world, so the page's own scripts cannot change what is
// recorded.
type targetDescriber struct {
	tab       cdp.Session
	mainFrame cdp.FrameID

	mu    sync.Mutex
	world runtime.ExecutionContextID
}

func (d *targetDescriber) at(ctx context.Context, x, y int64) *session.WebTarget {
	yes := true
	loc, err := cdp.Call(ctx, d.tab, dom.GetNodeForLocation, dom.GetNodeForLocationParams{X: x, Y: y, IgnorePointerEventsNone: &yes})
	if err != nil || loc.BackendNodeID == 0 {
		return nil
	}
	tree, err := cdp.Call(ctx, d.tab, accessibility.GetPartialAXTree, accessibility.GetPartialAXTreeParams{BackendNodeID: loc.BackendNodeID, FetchRelatives: &yes})
	if err != nil {
		return nil
	}
	chosen := pickTargetNode(tree.Nodes, loc.BackendNodeID)
	backendID := loc.BackendNodeID
	var role, name string
	if chosen != nil {
		backendID, role, name = chosen.BackendDOMNodeID, axString(chosen.Role), axString(chosen.Name)
	}
	depth := int64(targetDOMDepth)
	described, err := cdp.Call(ctx, d.tab, dom.DescribeNode, dom.DescribeNodeParams{BackendNodeID: backendID, Depth: &depth})
	if err != nil || described.Node == nil {
		return nil
	}
	return buildTarget(described.Node, role, name)
}

// focused describes the element with keyboard focus, and reports whether it takes typed text.
func (d *targetDescriber) focused(ctx context.Context) (*session.WebTarget, bool) {
	object, err := d.activeElement(ctx)
	if err != nil || object == "" {
		return nil, false
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, _ = cdp.Call(releaseCtx, d.tab, runtime.ReleaseObjectGroup, runtime.ReleaseObjectGroupParams{ObjectGroup: targetObjectGroup})
	}()
	depth := int64(targetDOMDepth)
	described, err := cdp.Call(ctx, d.tab, dom.DescribeNode, dom.DescribeNodeParams{ObjectID: object, Depth: &depth})
	if err != nil || described.Node == nil {
		return nil, false
	}
	var role, name string
	if tree, err := cdp.Call(ctx, d.tab, accessibility.GetPartialAXTree, accessibility.GetPartialAXTreeParams{ObjectID: object}); err == nil {
		for _, n := range tree.Nodes {
			if n.BackendDOMNodeID == described.Node.BackendNodeID {
				role, name = axString(n.Role), axString(n.Name)
				break
			}
		}
	}
	return buildTarget(described.Node, role, name), takesText(described.Node, role)
}

func (d *targetDescriber) activeElement(ctx context.Context) (runtime.RemoteObjectID, error) {
	for attempt := 0; ; attempt++ {
		world, err := d.isolatedWorld(ctx, attempt > 0)
		if err != nil {
			return "", err
		}
		res, err := cdp.Call(ctx, d.tab, runtime.Evaluate, runtime.EvaluateParams{
			Expression:  "document.activeElement",
			ContextID:   world,
			ObjectGroup: targetObjectGroup,
		})
		// A navigation destroys the isolated world, so make a new one once.
		if err != nil && attempt == 0 {
			continue
		}
		if err != nil || res.Result == nil {
			return "", err
		}
		return res.Result.ObjectID, nil
	}
}

func (d *targetDescriber) isolatedWorld(ctx context.Context, renew bool) (runtime.ExecutionContextID, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.world != 0 && !renew {
		return d.world, nil
	}
	res, err := cdp.Call(ctx, d.tab, page.CreateIsolatedWorld, page.CreateIsolatedWorldParams{FrameID: d.mainFrame, WorldName: targetObjectGroup})
	if err != nil {
		return 0, err
	}
	d.world = res.ExecutionContextID
	return d.world, nil
}

// pickTargetNode walks up from the node under the pointer to the element the user meant, such as
// the link around the text that was clicked.
func pickTargetNode(nodes []*accessibility.Node, start cdp.BackendNodeID) *accessibility.Node {
	byID := make(map[accessibility.NodeID]*accessibility.Node, len(nodes))
	var current *accessibility.Node
	for _, n := range nodes {
		byID[n.NodeID] = n
		if n.BackendDOMNodeID == start {
			current = n
		}
	}
	var fallback *accessibility.Node
	for n, seen := current, 0; n != nil && seen < len(nodes); n, seen = byID[n.ParentID], seen+1 {
		role := axString(n.Role)
		if interactiveRoles[role] {
			return n
		}
		if fallback == nil && !n.Ignored && n.BackendDOMNodeID != 0 && role != "StaticText" && role != "InlineTextBox" {
			fallback = n
		}
	}
	return fallback
}

func axString(v *accessibility.Value) string {
	if v == nil || len(v.Value) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(v.Value, &s); err != nil {
		return ""
	}
	return s
}

// buildTarget keeps what identifies an element and never what a user typed into it: fields
// record no text, and a password field records nothing beyond its tag and role.
func buildTarget(node *cdp.Node, role, name string) *session.WebTarget {
	tag := strings.ToLower(node.LocalName)
	if tag == "" {
		tag = strings.ToLower(node.NodeName)
	}
	target := &session.WebTarget{Tag: tag, Role: role}
	attrs := attributes(node)
	if tag == "input" && strings.EqualFold(attrs["type"], "password") {
		return target
	}
	target.Name = truncateText(name)
	if isField(tag, attrs, role) {
		return target
	}
	target.Text = truncateText(visibleText(node))
	return target
}

func isField(tag string, attrs map[string]string, role string) bool {
	switch tag {
	case "input", "textarea", "select":
		return true
	}
	if editable, ok := attrs["contenteditable"]; ok && !strings.EqualFold(editable, "false") {
		return true
	}
	return fieldRoles[role]
}

// takesText reports whether Enter on the element submits what was typed. A textarea is left out,
// because Enter there only starts a new line.
func takesText(node *cdp.Node, role string) bool {
	tag := strings.ToLower(node.LocalName)
	attrs := attributes(node)
	if tag == "input" {
		return !nonTextInputTypes[strings.ToLower(attrs["type"])]
	}
	if tag == "textarea" {
		return false
	}
	return isField(tag, attrs, role)
}

func attributes(node *cdp.Node) map[string]string {
	attrs := make(map[string]string, len(node.Attributes)/2)
	for i := 0; i+1 < len(node.Attributes); i += 2 {
		attrs[strings.ToLower(node.Attributes[i])] = node.Attributes[i+1]
	}
	return attrs
}

func visibleText(node *cdp.Node) string {
	var b strings.Builder
	var walk func(n *cdp.Node)
	walk = func(n *cdp.Node) {
		if utf8.RuneCountInString(b.String()) > maxTargetChars {
			return
		}
		switch strings.ToLower(n.LocalName) {
		case "script", "style", "noscript", "template":
			return
		}
		if n.NodeType == 3 {
			b.WriteString(n.NodeValue)
			b.WriteByte(' ')
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	walk(node)
	return strings.Join(strings.Fields(b.String()), " ")
}

func truncateText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= maxTargetChars {
		return s
	}
	return string([]rune(s)[:maxTargetChars])
}
