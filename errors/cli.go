package errors

import (
	"fmt"
	"os"
)

// PrintCLI prints a formatted error card to stderr.
func PrintCLI(err *Error) {
	fmt.Fprintf(os.Stderr, "\n  ✗ %s\n", err.Message)
	fmt.Fprintf(os.Stderr, "    code: %s\n", err.Code)
	if err.Fix != "" {
		fmt.Fprintf(os.Stderr, "    fix:  %s\n", err.Fix)
	}
	fmt.Fprintln(os.Stderr)
}

// PrintCLIDetailed prints a detailed error card with got/expected values.
func PrintCLIDetailed(msg, got, expected, fix string) {
	fmt.Fprintf(os.Stderr, "\n  ✗ %s\n", msg)
	if got != "" {
		fmt.Fprintf(os.Stderr, "    got:      %s\n", got)
	}
	if expected != "" {
		fmt.Fprintf(os.Stderr, "    expected: %s\n", expected)
	}
	if fix != "" {
		fmt.Fprintf(os.Stderr, "    fix:      %s\n", fix)
	}
	fmt.Fprintln(os.Stderr)
}
