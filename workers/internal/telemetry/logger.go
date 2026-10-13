// Package telemetry provides structured JSON logging with secret redaction.
package telemetry

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "debug"
	case Info:
		return "info"
	case Warn:
		return "warn"
	default:
		return "error"
	}
}

type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	min      Level
	bindings map[string]any
}

func New(out io.Writer, min Level) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{out: out, min: min, bindings: map[string]any{}}
}

func (l *Logger) Child(kv map[string]any) *Logger {
	merged := map[string]any{}
	for k, v := range l.bindings {
		merged[k] = v
	}
	for k, v := range kv {
		merged[k] = v
	}
	return &Logger{out: l.out, min: l.min, bindings: merged}
}

func (l *Logger) log(level Level, msg string, fields map[string]any) {
	if level < l.min {
		return
	}
	rec := map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
		"level": level.String(),
		"msg":   msg,
	}
	for k, v := range l.bindings {
		rec[k] = RedactValue(v)
	}
	for k, v := range fields {
		rec[k] = RedactValue(v)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(b, '\n'))
}

func (l *Logger) Debug(msg string, f map[string]any) { l.log(Debug, msg, f) }
func (l *Logger) Info(msg string, f map[string]any)  { l.log(Info, msg, f) }
func (l *Logger) Warn(msg string, f map[string]any)  { l.log(Warn, msg, f) }
func (l *Logger) Error(msg string, f map[string]any) { l.log(Error, msg, f) }

const Redacted = "[REDACTED]"

var sensitiveKey = regexp.MustCompile(`(?i)(^|[_-])(pass(word|wd)?|secret|token|api[_-]?key|auth(orization)?|cookie|credential|private[_-]?key|session[_-]?id|bearer|access[_-]?key|signing[_-]?secret)([_-]|$)`)

var valuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*`),
	regexp.MustCompile(`://[^/\s:@]+:[^/\s:@]+@`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`),
}

// RedactString scrubs known secret-shaped substrings.
func RedactString(s string) string {
	for _, re := range valuePatterns {
		s = re.ReplaceAllString(s, Redacted)
	}
	return s
}

// RedactValue recursively redacts maps, slices, and strings.
func RedactValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return RedactString(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if sensitiveKey.MatchString(k) {
				out[k] = Redacted
			} else {
				out[k] = RedactValue(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = RedactValue(val)
		}
		return out
	case error:
		return RedactString(t.Error())
	default:
		return v
	}
}

// IsSensitiveKey reports whether a field name denotes sensitive data.
func IsSensitiveKey(k string) bool { return sensitiveKey.MatchString(strings.TrimSpace(k)) }
