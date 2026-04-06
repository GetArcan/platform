package errors

// Error code constants.
const (
	CodeNotFound    = "not_found"
	CodeValidation  = "validation"
	CodeForbidden   = "forbidden"
	CodeUnauthorized = "unauthorized"
	CodeConflict    = "conflict"
	CodeRateLimited = "rate_limited"
	CodeEngineError = "engine_error"
	CodeUnavailable = "unavailable"
	CodeInternal    = "internal"
)

// StatusFromCode returns the HTTP status code for a given error code.
// Unknown codes default to 500.
func StatusFromCode(code string) int {
	switch code {
	case CodeNotFound:
		return 404
	case CodeValidation:
		return 400
	case CodeForbidden:
		return 403
	case CodeUnauthorized:
		return 401
	case CodeConflict:
		return 409
	case CodeRateLimited:
		return 429
	case CodeEngineError:
		return 502
	case CodeUnavailable:
		return 503
	case CodeInternal:
		return 500
	default:
		return 500
	}
}
