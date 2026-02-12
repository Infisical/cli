package templates

import (
	"embed"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

//go:embed *.tmpl
var TemplatesFS embed.FS

func CompileTemplateFunctions(customFunctions template.FuncMap) template.FuncMap {

	templates := customFunctions

	sprigFuncs := sprig.TxtFuncMap()
	// removed for security reasons
	delete(sprigFuncs, "env")
	delete(sprigFuncs, "expandenv")

	for k, v := range sprigFuncs {
		// make sure we aren't overwriting any of our own functions
		_, exists := templates[k]
		if !exists {
			templates[k] = v
		}
	}

	return templates
}
