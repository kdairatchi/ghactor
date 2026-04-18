package gen

import "embed"

//go:embed templates/*.yml
var templateFS embed.FS
