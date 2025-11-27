package templates

import (
	"embed"
)

//go:embed *.tmpl
var TemplatesFS embed.FS
