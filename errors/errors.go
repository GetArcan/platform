package errors

import "fmt"

// Error is a structured error with an error code, HTTP status, and optional
// recovery guidance. It implements the error and Unwrap interfaces.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"error"`
	Status  int    `json:"-"`
	Fix     string `json:"fix,omitempty"`
	Field   string `json:"field,omitempty"`
	Cause   error  `json:"-"`
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.Cause }

// WithFix sets a recovery hint on the error.
func (e *Error) WithFix(fix string) *Error {
	e.Fix = fix
	return e
}

// WithField sets the field name that caused the error.
func (e *Error) WithField(field string) *Error {
	e.Field = field
	return e
}

// WithCause attaches an underlying error for Unwrap compatibility.
func (e *Error) WithCause(err error) *Error {
	e.Cause = err
	return e
}

func newError(code string, status int, format string, args ...any) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Status:  status,
	}
}

// NotFound creates a 404 error.
func NotFound(format string, args ...any) *Error {
	return newError(CodeNotFound, 404, format, args...)
}

// Validation creates a 400 error.
func Validation(format string, args ...any) *Error {
	return newError(CodeValidation, 400, format, args...)
}

// Forbidden creates a 403 error.
func Forbidden(format string, args ...any) *Error {
	return newError(CodeForbidden, 403, format, args...)
}

// Unauthorized creates a 401 error.
func Unauthorized(format string, args ...any) *Error {
	return newError(CodeUnauthorized, 401, format, args...)
}

// Conflict creates a 409 error.
func Conflict(format string, args ...any) *Error {
	return newError(CodeConflict, 409, format, args...)
}

// RateLimited creates a 429 error.
func RateLimited(format string, args ...any) *Error {
	return newError(CodeRateLimited, 429, format, args...)
}

// EngineError creates a 502 error.
func EngineError(format string, args ...any) *Error {
	return newError(CodeEngineError, 502, format, args...)
}

// Unavailable creates a 503 error.
func Unavailable(format string, args ...any) *Error {
	return newError(CodeUnavailable, 503, format, args...)
}

// Internal creates a 500 error.
func Internal(format string, args ...any) *Error {
	return newError(CodeInternal, 500, format, args...)
}
