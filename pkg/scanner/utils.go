package scanner

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// titleCase converts s to title case using Unicode-aware rules.
// It replaces the deprecated strings.Title function.
func titleCase(s string) string {
	return cases.Title(language.English).String(s)
}
