package frameworks

import (
	"path/filepath"
	"strings"
)

var compoundTemplateExtensions = []string{
	".blade.php",
	".thymeleaf.html",
}

// DetectTemplateExtension returns a precise template extension for known
// framework template files, including compound suffixes such as .blade.php.
// It falls back to filepath.Ext for non-template files.
func DetectTemplateExtension(path string) string {
	lower := strings.ToLower(path)
	for _, ext := range compoundTemplateExtensions {
		if strings.HasSuffix(lower, ext) {
			return ext
		}
	}
	return strings.ToLower(filepath.Ext(path))
}
