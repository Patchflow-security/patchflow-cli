package frameworks

// Signatures returns the detection signatures for all known framework packs.
// Order is not significant; the detector evaluates all signatures and keeps
// those whose minimum signal threshold is met.
//
// Signatures are deliberately conservative: a framework is only reported when
// enough independent signals match, which keeps false detections out of the
// rule-pack activation path.
func Signatures() []Signature {
	return []Signature{
		// === Ruby ===
		{
			Name:       NameRails,
			Language:   "ruby",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "Gemfile", Contains: "rails"},
				{Kind: SignalFileContains, Path: "Gemfile.lock", Contains: "rails"},
				{Kind: SignalFilePresent, Path: "config/routes.rb"},
				{Kind: SignalFilePresent, Path: "app/controllers"},
				{Kind: SignalGlobMatch, Glob: "app/views/**/*.erb"},
			},
			FileExtensions:      []string{".rb"},
			TemplateExtensions:  []string{".erb", ".rhtml", ".haml", ".slim"},
		},
		{
			Name:       NameSinatra,
			Language:   "ruby",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "Gemfile", Contains: "sinatra"},
				{Kind: SignalFileContains, Path: "Gemfile.lock", Contains: "sinatra"},
			},
			FileExtensions:     []string{".rb"},
			TemplateExtensions: []string{".erb"},
		},

		// === Python ===
		{
			Name:       NameDjango,
			Language:   "python",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFilePresent, Path: "manage.py"},
				{Kind: SignalFileContains, Path: "settings.py", Contains: "installed_apps"},
				{Kind: SignalFileContains, Path: "settings.py", Contains: "django"},
				{Kind: SignalFilePresent, Path: "urls.py"},
				{Kind: SignalGlobMatch, Glob: "templates/**/*.html"},
			},
			FileExtensions:     []string{".py"},
			TemplateExtensions: []string{".html", ".jinja", ".jinja2"},
		},
		{
			Name:       NameFlask,
			Language:   "python",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "requirements.txt", Contains: "flask"},
				{Kind: SignalFileContains, Path: "pyproject.toml", Contains: "flask"},
				{Kind: SignalFileContains, Path: "Pipfile", Contains: "flask"},
			},
			FileExtensions:     []string{".py"},
			TemplateExtensions: []string{".html", ".jinja", ".jinja2"},
		},
		{
			Name:       NameFastAPI,
			Language:   "python",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "requirements.txt", Contains: "fastapi"},
				{Kind: SignalFileContains, Path: "pyproject.toml", Contains: "fastapi"},
				{Kind: SignalFileContains, Path: "Pipfile", Contains: "fastapi"},
			},
			FileExtensions:     []string{".py"},
			TemplateExtensions: []string{".html", ".jinja", ".jinja2"},
		},
		{
			Name:       NameGraphQL,
			Language:   "python",
			MinSignals: 1,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "requirements.txt", Contains: "graphene"},
				{Kind: SignalFileContains, Path: "requirements.txt", Contains: "ariadne"},
				{Kind: SignalFileContains, Path: "requirements.txt", Contains: "strawberry-graphql"},
				{Kind: SignalFileContains, Path: "requirements.txt", Contains: "graphql-core"},
				{Kind: SignalFileContains, Path: "pyproject.toml", Contains: "graphene"},
				{Kind: SignalFileContains, Path: "pyproject.toml", Contains: "ariadne"},
				{Kind: SignalFileContains, Path: "pyproject.toml", Contains: "strawberry"},
				{Kind: SignalGlobMatch, Glob: "**/*.graphql"},
				{Kind: SignalGlobMatch, Glob: "**/schema.graphql"},
			},
			FileExtensions:     []string{".py"},
			TemplateExtensions: []string{},
		},

		// === PHP ===
		{
			Name:       NameLaravel,
			Language:   "php",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFilePresent, Path: "artisan"},
				{Kind: SignalFileContains, Path: "composer.json", Contains: "laravel/framework"},
				{Kind: SignalFilePresent, Path: "routes/web.php"},
				{Kind: SignalGlobMatch, Glob: "resources/views/**/*.blade.php"},
			},
			FileExtensions:     []string{".php"},
			TemplateExtensions: []string{".blade.php", ".twig", ".phtml"},
		},
		{
			Name:       NameSymfony,
			Language:   "php",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "composer.json", Contains: "symfony/"},
				{Kind: SignalFilePresent, Path: "bin/console"},
				{Kind: SignalGlobMatch, Glob: "templates/**/*.twig"},
			},
			FileExtensions:     []string{".php"},
			TemplateExtensions: []string{".twig", ".php"},
		},
		{
			Name:       NameWordPress,
			Language:   "php",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "wp-config.php", Contains: "wp-settings.php"},
				{Kind: SignalFilePresent, Path: "wp-includes"},
				{Kind: SignalFilePresent, Path: "wp-content"},
			},
			FileExtensions:     []string{".php"},
			TemplateExtensions: []string{".php", ".phtml"},
		},

		// === Java ===
		{
			Name:       NameSpring,
			Language:   "java",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "pom.xml", Contains: "spring-boot"},
				{Kind: SignalFileContains, Path: "build.gradle", Contains: "spring-boot"},
				{Kind: SignalFileContains, Path: "build.gradle", Contains: "org.springframework.boot"},
				{Kind: SignalGlobMatch, Glob: "src/main/resources/application.yml"},
				{Kind: SignalGlobMatch, Glob: "src/main/resources/application.properties"},
				{Kind: SignalGlobMatch, Glob: "src/main/java/**/*Application.java"},
				{Kind: SignalGlobMatch, Glob: "src/main/resources/templates/**/*.html"},
			},
			FileExtensions:     []string{".java"},
			TemplateExtensions: []string{".jsp", ".jspx", ".ftl", ".vm", ".html", ".thymeleaf.html"},
		},
		{
			Name:       NameSpringSec,
			Language:   "java",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "pom.xml", Contains: "spring-security"},
				{Kind: SignalFileContains, Path: "build.gradle", Contains: "spring-security"},
				{Kind: SignalFileContains, Path: "build.gradle", Contains: "org.springframework.security"},
				{Kind: SignalGlobMatch, Glob: "src/main/java/**/*SecurityConfig*.java"},
			},
			FileExtensions:     []string{".java"},
			TemplateExtensions: []string{},
		},

		// === C# / .NET ===
		{
			Name:       NameASPNET,
			Language:   "csharp",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalGlobMatch, Glob: "**/*.csproj"},
				{Kind: SignalFileContains, Path: "Program.cs", Contains: "Microsoft.AspNetCore"},
				{Kind: SignalFileContains, Path: "Startup.cs", Contains: "Microsoft.AspNetCore"},
				{Kind: SignalGlobMatch, Glob: "Controllers/**/*.cs"},
			},
			FileExtensions:     []string{".cs"},
			TemplateExtensions: []string{".cshtml", ".razor"},
		},
		{
			Name:       NameRazor,
			Language:   "csharp",
			MinSignals: 1,
			Signals: []Signal{
				{Kind: SignalGlobMatch, Glob: "**/*.cshtml"},
				{Kind: SignalGlobMatch, Glob: "**/*.razor"},
			},
			FileExtensions:     []string{".cshtml", ".razor"},
			TemplateExtensions: []string{".cshtml", ".razor"},
		},

		// === JavaScript / TypeScript ===
		{
			Name:       NameExpress,
			Language:   "javascript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "package.json", Contains: "\"express\""},
				{Kind: SignalFileContains, Path: "package.json", Contains: "express"},
			},
			FileExtensions:     []string{".js", ".mjs", ".cjs", ".ts"},
			TemplateExtensions: []string{".ejs", ".hbs", ".pug"},
		},
		{
			Name:       NameNextJS,
			Language:   "javascript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFilePresent, Path: "next.config.js"},
				{Kind: SignalFilePresent, Path: "next.config.mjs"},
				{Kind: SignalFilePresent, Path: "next.config.ts"},
				{Kind: SignalFilePresent, Path: "pages"},
				{Kind: SignalFilePresent, Path: "app"},
				{Kind: SignalFileContains, Path: "package.json", Contains: "next"},
			},
			FileExtensions:     []string{".js", ".jsx", ".ts", ".tsx"},
			TemplateExtensions: []string{".jsx", ".tsx"},
		},
		{
			Name:       NameReact,
			Language:   "javascript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "package.json", Contains: "\"react\""},
				{Kind: SignalFileContains, Path: "package.json", Contains: "react-dom"},
				{Kind: SignalGlobMatch, Glob: "src/**/*.jsx"},
				{Kind: SignalGlobMatch, Glob: "src/**/*.tsx"},
			},
			FileExtensions:     []string{".jsx", ".tsx"},
			TemplateExtensions: []string{".jsx", ".tsx"},
		},
		{
			Name:       NameAngular,
			Language:   "typescript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "package.json", Contains: "@angular/core"},
				{Kind: SignalFilePresent, Path: "angular.json"},
			},
			FileExtensions:     []string{".ts"},
			TemplateExtensions: []string{".html"},
		},
		{
			Name:       NameNestJS,
			Language:   "typescript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "package.json", Contains: "@nestjs/core"},
				{Kind: SignalFilePresent, Path: "nest-cli.json"},
			},
			FileExtensions:     []string{".ts"},
			TemplateExtensions: []string{},
		},
		{
			Name:       NameVue,
			Language:   "javascript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "package.json", Contains: "\"vue\""},
				{Kind: SignalGlobMatch, Glob: "src/**/*.vue"},
			},
			FileExtensions:     []string{".js", ".ts", ".vue"},
			TemplateExtensions: []string{".vue"},
		},
		{
			Name:       NameNuxt,
			Language:   "javascript",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "package.json", Contains: "nuxt"},
				{Kind: SignalFilePresent, Path: "nuxt.config.js"},
				{Kind: SignalFilePresent, Path: "nuxt.config.ts"},
			},
			FileExtensions:     []string{".js", ".ts", ".vue"},
			TemplateExtensions: []string{".vue"},
		},

		// === Go ===
		{
			Name:       NameGin,
			Language:   "go",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "go.mod", Contains: "github.com/gin-gonic/gin"},
				{Kind: SignalFileContains, Path: "go.sum", Contains: "github.com/gin-gonic/gin"},
			},
			FileExtensions:     []string{".go"},
			TemplateExtensions: []string{},
		},
		{
			Name:       NameEcho,
			Language:   "go",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "go.mod", Contains: "github.com/labstack/echo"},
				{Kind: SignalFileContains, Path: "go.sum", Contains: "github.com/labstack/echo"},
			},
			FileExtensions:     []string{".go"},
			TemplateExtensions: []string{},
		},
		{
			Name:       NameFiber,
			Language:   "go",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "go.mod", Contains: "github.com/gofiber/fiber"},
				{Kind: SignalFileContains, Path: "go.sum", Contains: "github.com/gofiber/fiber"},
			},
			FileExtensions:     []string{".go"},
			TemplateExtensions: []string{},
		},
		{
			Name:       NameChi,
			Language:   "go",
			MinSignals: 2,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "go.mod", Contains: "github.com/go-chi/chi"},
				{Kind: SignalFileContains, Path: "go.sum", Contains: "github.com/go-chi/chi"},
			},
			FileExtensions:     []string{".go"},
			TemplateExtensions: []string{},
		},
		{
			Name:       NameNetHTTP,
			Language:   "go",
			MinSignals: 1,
			Signals: []Signal{
				{Kind: SignalFileContains, Path: "go.mod", Contains: "net/http"},
			},
			FileExtensions:     []string{".go"},
			TemplateExtensions: []string{},
		},
	}
}

// SignatureByName returns the signature for a framework, or nil if unknown.
func SignatureByName(n Name) *Signature {
	for i := range signaturesCache {
		if signaturesCache[i].Name == n {
			return &signaturesCache[i]
		}
	}
	return nil
}

var signaturesCache = Signatures()
