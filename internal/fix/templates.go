// Fix templates for common vulnerability patterns.
package fix

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Patchflow-security/patchflow-cli/internal/analysis"
)

// builtinTemplates returns all built-in fix templates.
func builtinTemplates() []FixTemplate {
	return []FixTemplate{
		// === JavaScript/TypeScript ===
		{
			RuleID:      "JS001",
			Languages:   []string{"javascript", "typescript"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceMedium,
			Description: "Replace eval() with JSON.parse() or Function constructor removal",
			Generate:    fixEval,
		},
		{
			RuleID:      "JS002",
			Languages:   []string{"javascript", "typescript"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceMedium,
			Description: "Replace new Function() with safer alternatives",
			Generate:    fixNewFunction,
		},
		{
			RuleID:      "JS003",
			Languages:   []string{"javascript", "typescript"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace child_process.exec with execFile (no shell)",
			Generate:    fixChildProcessExec,
		},
		{
			RuleID:      "JS004",
			Languages:   []string{"javascript", "typescript"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace child_process.execSync with execFileSync (no shell)",
			Generate:    fixChildProcessExecSync,
		},
		{
			RuleID:      "JS005",
			Languages:   []string{"javascript", "typescript"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceMedium,
			Description: "Replace SQL string interpolation with parameterized queries",
			Generate:    fixJSSQLInjection,
		},
		{
			RuleID:      "JS006",
			Languages:   []string{"javascript", "typescript"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceMedium,
			Description: "Replace innerHTML with textContent",
			Generate:    fixInnerHTML,
		},

		// === Python ===
		{
			RuleID:      "PY001",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceMedium,
			Description: "Replace eval() with ast.literal_eval() or JSON parsing",
			Generate:    fixEval,
		},
		{
			RuleID:      "PY002",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceMedium,
			Description: "Remove or replace exec() with safer alternatives",
			Generate:    fixPythonExec,
		},
		{
			RuleID:      "PY003",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace os.system() with subprocess.run() without shell",
			Generate:    fixOsSystem,
		},
		{
			RuleID:      "PY004",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Set shell=False in subprocess call",
			Generate:    fixSubprocessShellTrue,
		},
		{
			RuleID:      "PY006",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace yaml.load() with yaml.safe_load()",
			Generate:    fixYamlLoad,
		},
		{
			RuleID:      "PY009",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace hashlib.md5() with hashlib.sha256()",
			Generate:    fixMD5,
		},
		{
			RuleID:      "PY010",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace hashlib.sha1() with hashlib.sha256()",
			Generate:    fixSHA1,
		},
		{
			RuleID:      "PY013",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Enable SSL verification",
			Generate:    fixSSLVerifyFalse,
		},
		{
			RuleID:      "PY014",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Remove verify=False from requests call",
			Generate:    fixRequestsVerifyFalse,
		},
		{
			RuleID:      "PY015",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Set debug=False",
			Generate:    fixDebugTrue,
		},
		{
			RuleID:      "PY016",
			Languages:   []string{"python"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Set debug=False in Flask app.run()",
			Generate:    fixFlaskDebug,
		},

		// === Go ===
		{
			RuleID:      "GO022",
			Languages:   []string{"go"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Set InsecureSkipVerify to false",
			Generate:    fixInsecureSkipVerify,
		},
		{
			RuleID:      "GO025",
			Languages:   []string{"go"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace exec.Command with sh -c with direct argument list",
			Generate:    fixGoExecShell,
		},
		{
			RuleID:      "GO026",
			Languages:   []string{"go"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace crypto/md5 with crypto/sha256",
			Generate:    fixGoMD5,
		},
		{
			RuleID:      "GO027",
			Languages:   []string{"go"},
			Strategy:    StrategyReplace,
			Confidence:  FixConfidenceHigh,
			Description: "Replace crypto/sha1 with crypto/sha256",
			Generate:    fixGoSHA1,
		},
	}
}

// === JavaScript/TypeScript Fixes ===

func fixEval(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	lang := detectLanguage(finding.FilePath)
	fixedLine := line
	replacement := "JSON.parse(/* your data */)"
	if lang == "python" {
		replacement = "ast.literal_eval(/* your data */)"
	}

	// Replace eval( with the safer alternative
	evalRe := regexp.MustCompile(`\beval\s*\(`)
	fixedLine = evalRe.ReplaceAllString(fixedLine, replacement+"(")

	if fixedLine == line {
		return nil, fmt.Errorf("no eval() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	// Add import for ast if Python
	if lang == "python" && !strings.Contains(source, "import ast") {
		fixedSource = "import ast\n" + fixedSource
		patch = generateUnifiedDiff(finding.FilePath, source, fixedSource)
	}

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace eval() with safe alternative",
		Description:   "eval() can execute arbitrary code. Replace with JSON.parse() (JS) or ast.literal_eval() (Python) for safe data parsing.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceMedium,
		Strategy:      StrategyReplace,
		Rationale:     "eval() executes arbitrary code. The replacement only parses data, not code.",
		References:    []string{"https://owasp.org/www-community/attacks/Code_Injection"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixNewFunction(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	// Replace new Function( with a comment and JSON.parse
	funcRe := regexp.MustCompile(`new\s+Function\s*\(`)
	fixedLine := funcRe.ReplaceAllString(line, "JSON.parse(/* */")
	if fixedLine == line {
		return nil, fmt.Errorf("no new Function() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace new Function() with JSON.parse()",
		Description:   "new Function() is equivalent to eval(). Replace with JSON.parse() for safe data parsing.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceMedium,
		Strategy:      StrategyReplace,
		Rationale:     "new Function() compiles and executes arbitrary code. JSON.parse() only parses data.",
		References:    []string{"https://owasp.org/www-community/attacks/Code_Injection"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixChildProcessExec(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	// Replace child_process.exec( with child_process.execFile(
	execRe := regexp.MustCompile(`child_process\.exec\s*\(`)
	fixedLine := execRe.ReplaceAllString(line, "child_process.execFile(")
	if fixedLine == line {
		return nil, fmt.Errorf("no child_process.exec() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace child_process.exec with execFile",
		Description:   "exec() runs commands in a shell, enabling command injection. execFile() runs the command directly without a shell.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "execFile() does not invoke a shell, preventing shell metacharacter injection.",
		References:    []string{"https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixChildProcessExecSync(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	execRe := regexp.MustCompile(`child_process\.execSync\s*\(`)
	fixedLine := execRe.ReplaceAllString(line, "child_process.execFileSync(")
	if fixedLine == line {
		return nil, fmt.Errorf("no child_process.execSync() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace child_process.execSync with execFileSync",
		Description:   "execSync() runs commands in a shell. execFileSync() runs the command directly without a shell.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "execFileSync() does not invoke a shell, preventing command injection.",
		References:    []string{"https://nodejs.org/api/child_process.html#child_processexecfilesyncfile-args-options"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixJSSQLInjection(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	// Replace template literal SQL with parameterized query
	// This is a conservative fix — we add a comment and suggest parameterized queries
	fixedLine := "// SECURITY: Use parameterized queries instead of string interpolation\n" + line
	if strings.Contains(line, "`") && strings.Contains(line, "${") {
		// Replace ${var} with ? placeholders
		templateRe := regexp.MustCompile(`\$\{[^}]+\}`)
		fixedLine = templateRe.ReplaceAllString(line, "?")
		fixedLine = "// SECURITY: Use parameterized queries — pass values as query params\n" + fixedLine
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Use parameterized SQL queries",
		Description:   "SQL queries with string interpolation are vulnerable to SQL injection. Use parameterized queries with ? placeholders.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceLow,
		Strategy:      StrategyReplace,
		Rationale:     "Parameterized queries separate code from data, preventing SQL injection.",
		References:    []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixInnerHTML(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	innerHTMLRe := regexp.MustCompile(`\.innerHTML\s*=`)
	fixedLine := innerHTMLRe.ReplaceAllString(line, ".textContent =")
	if fixedLine == line {
		return nil, fmt.Errorf("no .innerHTML= found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace innerHTML with textContent",
		Description:   "innerHTML can execute HTML/JavaScript injection (XSS). textContent safely sets text without parsing HTML.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "textContent does not parse HTML, preventing XSS attacks.",
		References:    []string{"https://owasp.org/www-community/attacks/xss/"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

// === Python Fixes ===

func fixPythonExec(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	execRe := regexp.MustCompile(`\bexec\s*\(`)
	fixedLine := execRe.ReplaceAllString(line, "# SECURITY: Remove exec() — use safe alternatives\n# exec(")
	if fixedLine == line {
		return nil, fmt.Errorf("no exec() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Remove exec() call",
		Description:   "exec() can execute arbitrary code. Remove it and use safe alternatives.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceLow,
		Strategy:      StrategyRemove,
		Rationale:     "exec() executes arbitrary code. The fix comments it out for manual review.",
		References:    []string{"https://owasp.org/www-community/attacks/Code_Injection"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixOsSystem(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	osSysRe := regexp.MustCompile(`os\.system\s*\(`)
	fixedLine := osSysRe.ReplaceAllString(line, "subprocess.run([], shell=False")
	if fixedLine == line {
		return nil, fmt.Errorf("no os.system() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	// Add import if not present
	if !strings.Contains(source, "import subprocess") {
		fixedSource = "import subprocess\n" + fixedSource
	}
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace os.system() with subprocess.run()",
		Description:   "os.system() is vulnerable to command injection. subprocess.run() with shell=False is safe.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "subprocess.run with shell=False does not invoke a shell, preventing injection.",
		References:    []string{"https://docs.python.org/3/library/subprocess.html#security-considerations"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixSubprocessShellTrue(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	shellRe := regexp.MustCompile(`(?i)shell\s*=\s*True`)
	fixedLine := shellRe.ReplaceAllString(line, "shell=False")
	if fixedLine == line {
		return nil, fmt.Errorf("no shell=True found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Set shell=False in subprocess call",
		Description:   "shell=True enables command injection. Set shell=False and pass arguments as a list.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "shell=False prevents shell metacharacter injection.",
		References:    []string{"https://docs.python.org/3/library/subprocess.html#security-considerations"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixYamlLoad(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	yamlRe := regexp.MustCompile(`\byaml\.load\s*\(`)
	fixedLine := yamlRe.ReplaceAllString(line, "yaml.safe_load(")
	if fixedLine == line {
		return nil, fmt.Errorf("no yaml.load() found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace yaml.load() with yaml.safe_load()",
		Description:   "yaml.load() can execute arbitrary code during deserialization. yaml.safe_load() only parses YAML data.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "yaml.safe_load() does not allow custom Python object construction.",
		References:    []string{"https://pyyaml.org/wiki/PyYAMLDocumentation"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixMD5(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	lang := detectLanguage(finding.FilePath)
	var md5Re *regexp.Regexp
	var replacement string

	if lang == "python" {
		md5Re = regexp.MustCompile(`hashlib\.md5`)
		replacement = "hashlib.sha256"
	} else if lang == "go" {
		md5Re = regexp.MustCompile(`crypto/md5`)
		replacement = "crypto/sha256"
	} else {
		md5Re = regexp.MustCompile(`\bmd5\b`)
		replacement = "sha256"
	}

	fixedLine := md5Re.ReplaceAllString(line, replacement)
	if fixedLine == line {
		return nil, fmt.Errorf("no MD5 reference found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace MD5 with SHA-256",
		Description:   "MD5 is cryptographically broken. Use SHA-256 for security-sensitive hashing.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "SHA-256 is a NIST-approved hash algorithm with no known vulnerabilities.",
		References:    []string{"https://csrc.nist.gov/projects/hash-functions"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixSHA1(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	lang := detectLanguage(finding.FilePath)
	var sha1Re *regexp.Regexp
	var replacement string

	if lang == "python" {
		sha1Re = regexp.MustCompile(`hashlib\.sha1`)
		replacement = "hashlib.sha256"
	} else if lang == "go" {
		sha1Re = regexp.MustCompile(`crypto/sha1`)
		replacement = "crypto/sha256"
	} else {
		sha1Re = regexp.MustCompile(`\bsha1\b`)
		replacement = "sha256"
	}

	fixedLine := sha1Re.ReplaceAllString(line, replacement)
	if fixedLine == line {
		return nil, fmt.Errorf("no SHA1 reference found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace SHA1 with SHA-256",
		Description:   "SHA1 is cryptographically broken. Use SHA-256 for security-sensitive hashing.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "SHA-256 is a NIST-approved hash algorithm with no known vulnerabilities.",
		References:    []string{"https://csrc.nist.gov/projects/hash-functions"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixSSLVerifyFalse(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	verifyRe := regexp.MustCompile(`(?i)(verify|ssl_verify|insecure)\s*=\s*False\b`)
	fixedLine := verifyRe.ReplaceAllString(line, "verify=True")
	if fixedLine == line {
		return nil, fmt.Errorf("no verify=False found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Enable SSL certificate verification",
		Description:   "Disabling SSL verification enables man-in-the-middle attacks. Enable certificate verification.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "SSL verification ensures you're connecting to the authentic server.",
		References:    []string{"https://owasp.org/www-community/attacks/Man-in-the-middle_attack"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixRequestsVerifyFalse(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	verifyRe := regexp.MustCompile(`(?i)verify\s*=\s*False`)
	fixedLine := verifyRe.ReplaceAllString(line, "verify=True")
	if fixedLine == line {
		return nil, fmt.Errorf("no verify=False found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Enable SSL verification in requests call",
		Description:   "verify=False disables SSL certificate checking, enabling MITM attacks.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "Always verify SSL certificates in production code.",
		References:    []string{"https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixDebugTrue(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	debugRe := regexp.MustCompile(`(?i)debug\s*=\s*True`)
	fixedLine := debugRe.ReplaceAllString(line, "debug=False")
	if fixedLine == line {
		return nil, fmt.Errorf("no debug=True found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Disable debug mode",
		Description:   "Debug mode should never be enabled in production. It can expose sensitive information and enable RCE.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyConfigure,
		Rationale:     "Debug mode exposes internal state and can lead to remote code execution.",
		References:    []string{"https://owasp.org/www-community/attacks/Code_Injection"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixFlaskDebug(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	debugRe := regexp.MustCompile(`(?i)debug\s*=\s*True`)
	fixedLine := debugRe.ReplaceAllString(line, "debug=False")
	if fixedLine == line {
		return nil, fmt.Errorf("no debug=True found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Disable Flask debug mode",
		Description:   "Flask debug=True exposes the Werkzeug debugger, which can lead to remote code execution.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyConfigure,
		Rationale:     "The Werkzeug debugger allows arbitrary code execution if accessed.",
		References:    []string{"https://flask.palletsprojects.com/en/latest/debugging/"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

// === Go Fixes ===

func fixInsecureSkipVerify(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	skipRe := regexp.MustCompile(`(?i)InsecureSkipVerify\s*:\s*true`)
	fixedLine := skipRe.ReplaceAllString(line, "InsecureSkipVerify: false")
	if fixedLine == line {
		return nil, fmt.Errorf("no InsecureSkipVerify:true found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Disable InsecureSkipVerify",
		Description:   "InsecureSkipVerify:true disables TLS certificate verification, enabling MITM attacks.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "TLS verification is essential for secure communications.",
		References:    []string{"https://owasp.org/www-community/attacks/Man-in-the-middle_attack"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixGoExecShell(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	// Replace exec.Command("sh", "-c", ...) with exec.Command(arg0, args...)
	shellRe := regexp.MustCompile(`exec\.Command\s*\(\s*["']sh["']\s*,\s*["']-c["']\s*,\s*`)
	fixedLine := shellRe.ReplaceAllString(line, "exec.Command(/* arg0 */, /* args... */ ")
	if fixedLine == line {
		return nil, fmt.Errorf("no exec.Command with sh -c found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Remove shell invocation from exec.Command",
		Description:   "exec.Command with sh -c is vulnerable to command injection. Pass the command and arguments directly.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceMedium,
		Strategy:      StrategyReplace,
		Rationale:     "Passing arguments directly avoids shell interpretation of metacharacters.",
		References:    []string{"https://pkg.go.dev/os/exec"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixGoMD5(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	md5Re := regexp.MustCompile(`crypto/md5`)
	fixedLine := md5Re.ReplaceAllString(line, "crypto/sha256")
	if fixedLine == line {
		return nil, fmt.Errorf("no crypto/md5 found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace crypto/md5 with crypto/sha256",
		Description:   "MD5 is cryptographically broken. Use SHA-256 from crypto/sha256.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "SHA-256 is a NIST-approved hash algorithm with no known vulnerabilities.",
		References:    []string{"https://csrc.nist.gov/projects/hash-functions"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

func fixGoSHA1(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	sha1Re := regexp.MustCompile(`crypto/sha1`)
	fixedLine := sha1Re.ReplaceAllString(line, "crypto/sha256")
	if fixedLine == line {
		return nil, fmt.Errorf("no crypto/sha1 found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace crypto/sha1 with crypto/sha256",
		Description:   "SHA1 is cryptographically broken. Use SHA-256 from crypto/sha256.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceHigh,
		Strategy:      StrategyReplace,
		Rationale:     "SHA-256 is a NIST-approved hash algorithm with no known vulnerabilities.",
		References:    []string{"https://csrc.nist.gov/projects/hash-functions"},
		AutoApplicable: true,
		CreatedAt:     now(),
	}, nil
}

// === Generic Fixes ===

func fixSQLInjection(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	// Generic SQL injection fix — add a comment and suggest parameterized queries
	fixedLine := "// SECURITY: Use parameterized queries instead of string concatenation\n" + line

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Use parameterized SQL queries",
		Description:   "SQL queries with string concatenation are vulnerable to SQL injection. Use parameterized queries.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceLow,
		Strategy:      StrategyAddValidation,
		Rationale:     "Parameterized queries separate code from data, preventing SQL injection.",
		References:    []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

func fixHardcodedSecret(finding analysis.Finding, source string) (*FixProposal, error) {
	line := extractLine(source, finding.LineStart)
	if line == "" {
		return nil, fmt.Errorf("could not extract line %d", finding.LineStart)
	}

	// Replace hardcoded secret with environment variable lookup
	lang := detectLanguage(finding.FilePath)
	var envLookup string
	switch lang {
	case "python":
		envLookup = "os.environ.get('SECRET_KEY')"
	case "javascript", "typescript":
		envLookup = "process.env.SECRET_KEY"
	case "go":
		envLookup = "os.Getenv(\"SECRET_KEY\")"
	default:
		envLookup = "/* Use environment variable */"
	}

	// Try to detect the variable name being assigned
	assignRe := regexp.MustCompile(`(?i)(password|passwd|pwd|api[_-]?key|apikey|secret)\s*=\s*["'][^"']+["']`)
	fixedLine := assignRe.ReplaceAllString(line, "$1 = "+envLookup)
	if fixedLine == line {
		return nil, fmt.Errorf("no hardcoded secret found on line %d", finding.LineStart)
	}

	fixedSource := replaceLine(source, finding.LineStart, fixedLine)
	patch := generateUnifiedDiff(finding.FilePath, source, fixedSource)

	return &FixProposal{
		ID:            fmt.Sprintf("fix-%s", finding.ID),
		FindingID:     finding.ID,
		RuleID:        finding.RuleID,
		Title:         "Replace hardcoded secret with environment variable",
		Description:   "Hardcoded secrets in source code are a security risk. Use environment variables or a secret manager.",
		Severity:      string(finding.Severity),
		FilePath:      finding.FilePath,
		LineStart:     finding.LineStart,
		LineEnd:       finding.LineStart,
		OriginalCode:  line,
		FixedCode:     fixedLine,
		Patch:         patch,
		Confidence:    FixConfidenceMedium,
		Strategy:      StrategyReplace,
		Rationale:     "Environment variables keep secrets out of source code and version control.",
		References:    []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
		AutoApplicable: false,
		CreatedAt:     now(),
	}, nil
}

// now returns the current UTC time.
func now() time.Time {
	return time.Now().UTC()
}
