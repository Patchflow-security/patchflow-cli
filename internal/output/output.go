package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Formatter defines how CLI output is presented to the user.
type Formatter interface {
	Print(data any) error
	PrintError(err error) error
	PrintSuccess(message string) error
	PrintTable(headers []string, rows [][]string) error
}

// HumanFormatter prints output in a human-readable format.
type HumanFormatter struct {
	w       io.Writer
	noColor bool
}

// JSONFormatter prints output as indented JSON.
type JSONFormatter struct {
	w io.Writer
}

// NewFormatter returns a Formatter based on the requested mode with default stdout.
func NewFormatter(jsonMode, noColor bool) Formatter {
	return NewWriter(os.Stdout, jsonMode, noColor)
}

// NewWriter returns a Formatter writing to w based on the requested mode.
func NewWriter(w io.Writer, jsonMode, noColor bool) Formatter {
	if jsonMode {
		return &JSONFormatter{w: w}
	}
	return &HumanFormatter{w: w, noColor: noColor}
}

// IsJSON reports whether f is a JSONFormatter.
func IsJSON(f Formatter) bool {
	_, ok := f.(*JSONFormatter)
	return ok
}

// Print writes data in a human-readable format.
func (h *HumanFormatter) Print(data any) error {
	switch v := data.(type) {
	case string:
		_, err := fmt.Fprintln(h.w, v)
		return err
	case fmt.Stringer:
		_, err := fmt.Fprintln(h.w, v.String())
		return err
	default:
		_, err := fmt.Fprintf(h.w, "%+v\n", data)
		return err
	}
}

// PrintError writes an error message.
func (h *HumanFormatter) PrintError(err error) error {
	if h.noColor {
		_, writeErr := fmt.Fprintf(h.w, "[ERR] error: %v\n", err)
		return writeErr
	}
	_, writeErr := fmt.Fprintf(h.w, "✗ error: %v\n", err)
	return writeErr
}

// PrintSuccess writes a success message.
func (h *HumanFormatter) PrintSuccess(message string) error {
	if h.noColor {
		_, err := fmt.Fprintf(h.w, "[OK] %s\n", message)
		return err
	}
	_, err := fmt.Fprintf(h.w, "✓ %s\n", message)
	return err
}

// PrintTable writes a simple column-aligned table.
func (h *HumanFormatter) PrintTable(headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return nil
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = max(len(h), 12)
	}
	for _, row := range rows {
		for i := 0; i < len(row) && i < len(widths); i++ {
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}

	var sb strings.Builder
	for i, h := range headers {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(padRight(h, widths[i]))
	}
	sb.WriteByte('\n')

	for _, row := range rows {
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				sb.WriteString("  ")
			}
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			sb.WriteString(padRight(cell, widths[i]))
		}
		sb.WriteByte('\n')
	}

	_, err := h.w.Write([]byte(sb.String()))
	return err
}

// Print marshals data to indented JSON and writes it.
func (j *JSONFormatter) Print(data any) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(j.w, string(b))
	return err
}

// PrintError marshals the error to indented JSON and writes it.
func (j *JSONFormatter) PrintError(err error) error {
	type errorOutput struct {
		Error string `json:"error"`
	}
	b, marshalErr := json.MarshalIndent(errorOutput{Error: err.Error()}, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	_, writeErr := fmt.Fprintln(j.w, string(b))
	return writeErr
}

// PrintSuccess marshals a success message to indented JSON and writes it.
func (j *JSONFormatter) PrintSuccess(message string) error {
	type successOutput struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	b, err := json.MarshalIndent(successOutput{Success: true, Message: message}, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(j.w, string(b))
	return err
}

// PrintTable marshals rows as a JSON array of objects with headers as keys.
func (j *JSONFormatter) PrintTable(headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return nil
	}

	out := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		obj := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(row) {
				obj[h] = row[i]
			} else {
				obj[h] = ""
			}
		}
		out = append(out, obj)
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(j.w, string(b))
	return err
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
