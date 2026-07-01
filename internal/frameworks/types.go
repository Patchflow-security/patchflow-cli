// Package frameworks detects web/application frameworks present in a project
// using lightweight filesystem and manifest signals. Detection output drives
// which framework rule packs the SAST engine activates.
//
// The detector is intentionally cheap: it reads small manifest files and
// checks for the presence of well-known paths. It does not parse application
// code. Confidence is derived from how many independent signals match.
package frameworks

// Name identifies a supported framework pack.
type Name string

const (
	NameRails       Name = "rails"
	NameDjango      Name = "django"
	NameFlask       Name = "flask"
	NameFastAPI     Name = "fastapi"
	NameLaravel     Name = "laravel"
	NameSymfony     Name = "symfony"
	NameSpring      Name = "spring"
	NameSpringSec   Name = "spring-security"
	NameASPNET      Name = "aspnet"
	NameRazor       Name = "razor"
	NameExpress     Name = "express"
	NameNextJS      Name = "nextjs"
	NameReact       Name = "react"
	NameAngular     Name = "angular"
	NameNestJS      Name = "nestjs"
	NameVue         Name = "vue"
	NameNuxt        Name = "nuxt"
	NameGin         Name = "gin"
	NameEcho        Name = "echo"
	NameFiber       Name = "fiber"
	NameChi         Name = "chi"
	NameNetHTTP     Name = "nethttp"
	NameSinatra     Name = "sinatra"
	NameWordPress   Name = "wordpress"
)

// SignalKind describes how a detection signal is verified.
type SignalKind int

const (
	// SignalFilePresent means the named file/dir exists relative to root.
	SignalFilePresent SignalKind = iota
	// SignalFileContains means the named file exists and contains a substring.
	SignalFileContains
	// SignalGlobMatch means at least one file matches a glob relative to root.
	SignalGlobMatch
)

// Signal is a single framework detection probe. Probes are independent; the
// more that match, the higher the detection confidence.
type Signal struct {
	Kind     SignalKind
	Path     string // relative to project root
	Contains string // substring to look for (SignalFileContains only), case-insensitive
	Glob     string // glob pattern relative to root (SignalGlobMatch only)
}

// Signature describes how to detect a single framework.
type Signature struct {
	Name        Name
	Language    string // primary language: ruby, python, php, java, csharp, javascript, typescript, go
	MinSignals  int    // minimum matched signals required for a positive detection
	Signals     []Signal
	// FileExtensions are source file extensions owned by this framework.
	FileExtensions []string
	// TemplateExtensions are template/view extensions owned by this framework.
	TemplateExtensions []string
}

// Detection is the result of detecting a single framework.
type Detection struct {
	Name       Name     `json:"name"`
	Language   string   `json:"language"`
	Confidence float64  `json:"confidence"` // 0.0–1.0, derived from matched/total signals
	Matched    []string `json:"matched"`     // human-readable descriptions of matched signals
}

// Result is the complete framework detection output for a project.
type Result struct {
	Frameworks []Detection `json:"frameworks"`
}
