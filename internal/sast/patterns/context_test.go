package patterns

import "testing"

func TestTrackerPythonTripleString(t *testing.T) {
	tr := NewTracker("python")

	// Line 1: code
	if ctx := tr.Context(`query = "SELECT * FROM users"`); ctx != ContextCode {
		t.Errorf("line 1: expected ContextCode, got %d", ctx)
	}
	tr.Advance(`query = "SELECT * FROM users"`)

	// Line 2: start of triple-quoted docstring
	if ctx := tr.Context(`prompt = """You are a security expert.`); ctx != ContextCode {
		t.Errorf("line 2: expected ContextCode (string opens on this line), got %d", ctx)
	}
	tr.Advance(`prompt = """You are a security expert.`)

	// Line 3: inside the triple-quoted string — should be ContextString
	if ctx := tr.Context(`Never use eval() or exec() in production.`); ctx != ContextString {
		t.Errorf("line 3: expected ContextString, got %d", ctx)
	}
	tr.Advance(`Never use eval() or exec() in production.`)

	// Line 4: still inside
	if ctx := tr.Context(`os.system() is also dangerous.`); ctx != ContextString {
		t.Errorf("line 4: expected ContextString, got %d", ctx)
	}
	tr.Advance(`os.system() is also dangerous.`)

	// Line 5: string closes, rest is code
	if ctx := tr.Context(`"""`); ctx != ContextCode {
		t.Errorf("line 5: expected ContextCode (string closes), got %d", ctx)
	}
	tr.Advance(`"""`)

	// Line 6: actual code with eval — should be ContextCode
	if ctx := tr.Context(`result = eval(user_input)`); ctx != ContextCode {
		t.Errorf("line 6: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerPythonSingleLineString(t *testing.T) {
	tr := NewTracker("python")

	// Single-line string with eval inside — should NOT trigger multi-line state
	line := `warning = "Don't use eval() in production"`
	if ctx := tr.Context(line); ctx != ContextCode {
		t.Errorf("single-line string: expected ContextCode, got %d", ctx)
	}
	tr.Advance(line)

	// Next line should not be in string context
	if ctx := tr.Context(`x = 1`); ctx != ContextCode {
		t.Errorf("after single-line string: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerPythonTripleSingleQuote(t *testing.T) {
	tr := NewTracker("python")

	tr.Advance(`text = '''This is a`)
	if ctx := tr.Context(`multi-line string with eval()`); ctx != ContextString {
		t.Errorf("triple single-quote: expected ContextString, got %d", ctx)
	}
	tr.Advance(`multi-line string with eval()`)
	tr.Advance(`'''`)

	// After closing, should be code
	if ctx := tr.Context(`y = 2`); ctx != ContextCode {
		t.Errorf("after closing triple single-quote: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerJSTemplateLiteral(t *testing.T) {
	tr := NewTracker("javascript")

	tr.Advance("const prompt = `You are an expert.")
	if ctx := tr.Context("Never use eval() in production."); ctx != ContextString {
		t.Errorf("JS template literal: expected ContextString, got %d", ctx)
	}
	tr.Advance("Never use eval() in production.")
	tr.Advance("`")

	if ctx := tr.Context("const x = 1;"); ctx != ContextCode {
		t.Errorf("after JS template literal: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerJSSingleLineBacktick(t *testing.T) {
	tr := NewTracker("typescript")

	// Single-line template literal — should not trigger multi-line
	line := "const x = `hello`"
	if ctx := tr.Context(line); ctx != ContextCode {
		t.Errorf("single-line backtick: expected ContextCode, got %d", ctx)
	}
	tr.Advance(line)

	if ctx := tr.Context("const y = 2;"); ctx != ContextCode {
		t.Errorf("after single-line backtick: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerRubyHeredoc(t *testing.T) {
	tr := NewTracker("ruby")

	tr.Advance(`text = <<HEREDOC`)
	if ctx := tr.Context(`This has eval() in it`); ctx != ContextString {
		t.Errorf("Ruby heredoc: expected ContextString, got %d", ctx)
	}
	tr.Advance(`This has eval() in it`)
	tr.Advance(`HEREDOC`)

	if ctx := tr.Context(`x = 1`); ctx != ContextCode {
		t.Errorf("after Ruby heredoc: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerRubyBeginEndBlock(t *testing.T) {
	tr := NewTracker("ruby")

	tr.Advance("=begin")
	if ctx := tr.Context("This is a comment with eval()"); ctx != ContextComment {
		t.Errorf("Ruby =begin block: expected ContextComment, got %d", ctx)
	}
	tr.Advance("This is a comment with eval()")
	tr.Advance("=end")

	if ctx := tr.Context("x = 1"); ctx != ContextCode {
		t.Errorf("after Ruby =end: expected ContextCode, got %d", ctx)
	}
}

func TestTrackerReset(t *testing.T) {
	tr := NewTracker("python")
	tr.inTripleD = true
	tr.Reset()
	if tr.inMultiLineString() {
		t.Error("Reset should clear multi-line string state")
	}
}

func TestTrackerPythonStringClosesAndReopensSameLine(t *testing.T) {
	tr := NewTracker("python")

	// A triple-string that closes and a new one opens on the same line
	line1 := `x = """short""" + """another`
	if ctx := tr.Context(line1); ctx != ContextCode {
		t.Errorf("closes-and-reopens line: expected ContextCode, got %d", ctx)
	}
	tr.Advance(line1)

	// Now we should be inside the second triple-string
	if ctx := tr.Context(`eval() inside string`); ctx != ContextString {
		t.Errorf("after reopens: expected ContextString, got %d", ctx)
	}
}
