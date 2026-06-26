// This file provides line-level context tracking for the regex-based
// pattern scanner. It tracks multi-line string literals (Python triple-quotes,
// JS/TS template literals, Ruby heredocs) so that security keywords appearing
// inside string content are not flagged as code.
//
// This is the non-cgo alternative to tree-sitter (P3.2): instead of building
// a full AST, we track lexical state across lines to determine whether a given
// line (or portion of a line) is inside a string literal, a comment, or actual
// code. This eliminates the documented false positives where eval/exec/os.system
// appear in docstrings, LLM prompt text, or multi-line template strings.
package patterns

// LineContext describes the lexical context of a line (or portion thereof).
type LineContext int

const (
	// ContextCode means the line is actual executable code.
	ContextCode LineContext = iota
	// ContextString means the line (or portion) is inside a multi-line string literal.
	ContextString
	// ContextComment means the line is a comment.
	ContextComment
)

// Tracker tracks multi-line lexical state across lines of a source file.
// It is language-aware: Python uses triple-quoted strings, JS/TS use
// backtick template literals, Ruby uses heredocs and =begin/=end blocks.
//
// Usage:
//
//	t := NewTracker(lang)
//	for each line:
//	  ctx := t.Context(line)
//	  if ctx == ContextCode { /* run pattern rules */ }
//	  t.Advance(line)
type Tracker struct {
	lang        string
	inTripleS   bool // inside ''' string (Python)
	inTripleD   bool // inside """ string (Python)
	inBacktick  bool // inside ` template literal (JS/TS) — only multi-line
	inHeredoc   bool // inside heredoc (Ruby)
	heredocTag  string
	inRubyBlock bool // inside =begin/=end block (Ruby)
}

// NewTracker creates a context tracker for the given language.
// Supported languages: "python", "javascript", "typescript", "ruby", "php".
func NewTracker(lang string) *Tracker {
	return &Tracker{lang: lang}
}

// Context returns the lexical context of the given line, considering
// multi-line state from previous lines. This is a pure query — it does
// NOT modify tracker state. Call Advance() after processing each line
// to update state.
//
// For lines that are partially in code and partially in a string,
// ContextCode is returned (the pattern scanner's per-line quote handling
// will filter string portions).
func (t *Tracker) Context(line string) LineContext {
	// If we're inside a multi-line string from a previous line, check if
	// it ends on this line. If it does, the portion after the closing
	// delimiter is code; if not, the whole line is string content.
	if t.inMultiLineString() {
		if t.peekEndsMultiLineString(line) {
			// The string ends on this line — the rest is code.
			return ContextCode
		}
		return ContextString
	}

	// Ruby =begin/=end comment blocks
	if t.lang == "ruby" && t.inRubyBlock {
		if stringsHasPrefix(trimSpace(line), "=end") {
			return ContextCode // ends on this line, rest is code
		}
		return ContextComment
	}

	return ContextCode
}

// Advance updates the tracker state after processing a line. This must
// be called for every line in order, even if the line was skipped due
// to being in ContextString.
func (t *Tracker) Advance(line string) {
	// If we're inside a multi-line string, handle closing and possible reopening
	if t.inMultiLineString() {
		t.advanceInString(line)
		return
	}

	// Ruby =begin/=end blocks
	if t.lang == "ruby" {
		if t.inRubyBlock {
			if stringsHasPrefix(trimSpace(line), "=end") {
				t.inRubyBlock = false
			}
			return
		}
		if stringsHasPrefix(trimSpace(line), "=begin") {
			t.inRubyBlock = true
			return
		}
	}

	t.scanLineOpen(line)
}

// advanceInString handles a line while inside a multi-line string. It
// checks if the string closes on this line and scans the remainder for
// new string openings.
func (t *Tracker) advanceInString(line string) {
	switch {
	case t.inTripleS:
		if idx := indexSafe(line, "'''"); idx >= 0 {
			t.inTripleS = false
			rest := line[idx+3:]
			t.scanLineOpen(rest)
		}
	case t.inTripleD:
		if idx := indexSafe(line, `"""`); idx >= 0 {
			t.inTripleD = false
			rest := line[idx+3:]
			t.scanLineOpen(rest)
		}
	case t.inBacktick:
		if idx := indexSafe(line, "`"); idx >= 0 {
			t.inBacktick = false
			rest := line[idx+1:]
			t.scanLineOpen(rest)
		}
	case t.inHeredoc:
		trimmed := trimSpace(line)
		if trimmed == t.heredocTag {
			t.inHeredoc = false
			t.heredocTag = ""
		}
	}
}

// inMultiLineString returns true if the tracker is currently inside a
// multi-line string literal from a previous line.
func (t *Tracker) inMultiLineString() bool {
	return t.inTripleS || t.inTripleD || t.inBacktick || t.inHeredoc
}

// peekEndsMultiLineString checks if the current line would close the open
// multi-line string. This is a pure query — it does NOT modify state.
func (t *Tracker) peekEndsMultiLineString(line string) bool {
	switch {
	case t.inTripleS:
		return indexSafe(line, "'''") >= 0
	case t.inTripleD:
		return indexSafe(line, `"""`) >= 0
	case t.inBacktick:
		return indexSafe(line, "`") >= 0
	case t.inHeredoc:
		return trimSpace(line) == t.heredocTag
	}
	return false
}

// scanLineOpen scans a line (or portion after a closing delimiter) for
// new multi-line string openings. It handles the case where a string
// opens and closes on the same line (not multi-line).
func (t *Tracker) scanLineOpen(line string) {
	i := 0
	for i < len(line) {
		// Skip single-line strings (don't track their content for multi-line)
		ch := line[i]

		// Python triple-quoted strings
		if t.lang == "python" {
			if i+2 < len(line) && line[i] == '\'' && line[i+1] == '\'' && line[i+2] == '\'' {
				// Check if it closes on the same line
				rest := line[i+3:]
				if idx := indexSafe(rest, "'''"); idx >= 0 {
					i = i + 3 + idx + 3
					continue
				}
				t.inTripleS = true
				return
			}
			if i+2 < len(line) && line[i] == '"' && line[i+1] == '"' && line[i+2] == '"' {
				rest := line[i+3:]
				if idx := indexSafe(rest, `"""`); idx >= 0 {
					i = i + 3 + idx + 3
					continue
				}
				t.inTripleD = true
				return
			}
			// Skip single-quoted strings
			if ch == '\'' || ch == '"' {
				closer := ch
				i++
				for i < len(line) && line[i] != closer {
					if line[i] == '\\' {
						i++ // skip escaped char
					}
					i++
				}
				i++
				continue
			}
		}

		// JS/TS template literals (backtick)
		if t.lang == "javascript" || t.lang == "typescript" {
			if ch == '`' {
				// Check if it closes on the same line
				rest := line[i+1:]
				if idx := indexSafe(rest, "`"); idx >= 0 {
					i = i + 1 + idx + 1
					continue
				}
				t.inBacktick = true
				return
			}
			// Skip single/double quoted strings
			if ch == '\'' || ch == '"' {
				closer := ch
				i++
				for i < len(line) && line[i] != closer {
					if line[i] == '\\' {
						i++
					}
					i++
				}
				i++
				continue
			}
		}

		// Ruby heredocs: <<TAG, <<~TAG, <<-TAG
		if t.lang == "ruby" {
			if ch == '\'' || ch == '"' {
				closer := ch
				i++
				for i < len(line) && line[i] != closer {
					if line[i] == '\\' {
						i++
					}
					i++
				}
				i++
				continue
			}
			// Detect heredoc start: <<TAG, <<~TAG, <<-TAG
			if ch == '<' && i+1 < len(line) && line[i+1] == '<' {
				j := i + 2
				if j < len(line) && (line[j] == '~' || line[j] == '-') {
					j++
				}
				if j < len(line) && (isAlpha(line[j]) || line[j] == '_') {
					start := j
					for j < len(line) && (isAlphaNum(line[j]) || line[j] == '_') {
						j++
					}
					tag := line[start:j]
					if tag != "" {
						// Check if heredoc body is on same line (rare) — we don't handle that
						t.inHeredoc = true
						t.heredocTag = tag
						return
					}
				}
			}
		}

		// PHP: skip single/double quoted strings
		if t.lang == "php" {
			if ch == '\'' || ch == '"' {
				closer := ch
				i++
				for i < len(line) && line[i] != closer {
					if line[i] == '\\' {
						i++
					}
					i++
				}
				i++
				continue
			}
		}

		i++
	}
}

// Reset clears the tracker state for reuse on a new file.
func (t *Tracker) Reset() {
	t.inTripleS = false
	t.inTripleD = false
	t.inBacktick = false
	t.inHeredoc = false
	t.heredocTag = ""
	t.inRubyBlock = false
}

// --- Minimal string helpers (avoid importing strings to keep package lean) ---

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func stringsHasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func indexSafe(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlphaNum(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9')
}
