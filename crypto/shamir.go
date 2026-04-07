package crypto

import (
	"crypto/rand"
	"fmt"
)

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).

// gf256Add returns a + b in GF(256). Addition in GF(256) is XOR.
func gf256Add(a, b byte) byte {
	return a ^ b
}

// gf256Mul returns a * b in GF(256) using Russian-peasant multiplication.
func gf256Mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B // reduction polynomial (x^8 + x^4 + x^3 + x + 1)
		}
		b >>= 1
	}
	return p
}

// gf256Inv returns the multiplicative inverse of a in GF(256).
// Returns 0 for input 0 (undefined, but safe for our use).
func gf256Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	// Use exponentiation: a^254 = a^(-1) in GF(256) since the group order is 255.
	result := a
	for i := 0; i < 6; i++ {
		result = gf256Mul(result, result)
		result = gf256Mul(result, a)
	}
	result = gf256Mul(result, result)
	return result
}

// gf256Div returns a / b in GF(256). Panics if b == 0.
func gf256Div(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(256)")
	}
	if a == 0 {
		return 0
	}
	return gf256Mul(a, gf256Inv(b))
}

// SplitKey splits a secret into n shares, requiring k shares to reconstruct.
// Uses Shamir's Secret Sharing over GF(256).
//
// Each share is len(secret)+1 bytes: the first byte is the share index (1-255),
// and the remaining bytes are the evaluated polynomial for each byte of the secret.
//
// Constraints: k >= 2, n >= k, n <= 255.
func SplitKey(secret []byte, n, k int) ([][]byte, error) {
	if k < 2 {
		return nil, fmt.Errorf("threshold k must be >= 2, got %d", k)
	}
	if n < k {
		return nil, fmt.Errorf("total shares n (%d) must be >= threshold k (%d)", n, k)
	}
	if n > 255 {
		return nil, fmt.Errorf("total shares n must be <= 255, got %d", n)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}

	// Allocate shares: each share = 1 byte index + len(secret) bytes of data.
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = byte(i + 1) // share indices are 1-based
	}

	// For each byte of the secret, generate a random polynomial of degree k-1
	// with the constant term equal to that byte, then evaluate at x=1..n.
	coeffs := make([]byte, k)
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		// coeffs[0] = secret byte (constant term)
		coeffs[0] = secret[byteIdx]

		// coeffs[1..k-1] = random
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("generating random coefficients: %w", err)
		}

		// Evaluate polynomial at each share's x value.
		for i := 0; i < n; i++ {
			x := byte(i + 1)
			shares[i][byteIdx+1] = evalPolynomial(coeffs, x)
		}
	}

	return shares, nil
}

// evalPolynomial evaluates a polynomial at x in GF(256) using Horner's method.
// coeffs[0] is the constant term, coeffs[deg] is the leading coefficient.
func evalPolynomial(coeffs []byte, x byte) byte {
	// Horner: result = coeffs[deg]
	// for i = deg-1 down to 0: result = result * x + coeffs[i]
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gf256Add(gf256Mul(result, x), coeffs[i])
	}
	return result
}

// CombineShares reconstructs the secret from k or more shares using
// Lagrange interpolation over GF(256).
//
// Each share must be in the format produced by SplitKey: first byte is the
// share index, remaining bytes are the data. All shares must have the same length.
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares, got %d", len(shares))
	}

	shareLen := len(shares[0])
	for i, s := range shares {
		if len(s) != shareLen {
			return nil, fmt.Errorf("share %d has length %d, expected %d", i, len(s), shareLen)
		}
		if shareLen < 2 {
			return nil, fmt.Errorf("share %d is too short", i)
		}
	}

	secretLen := shareLen - 1
	secret := make([]byte, secretLen)

	// Extract x-coordinates (share indices).
	xs := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s[0]
		if xs[i] == 0 {
			return nil, fmt.Errorf("share %d has invalid index 0", i)
		}
	}

	// Lagrange interpolation at x=0 for each byte position.
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		var value byte
		for i := 0; i < len(shares); i++ {
			yi := shares[i][byteIdx+1]

			// Compute Lagrange basis polynomial l_i(0).
			var num byte = 1
			var den byte = 1
			for j := 0; j < len(shares); j++ {
				if i == j {
					continue
				}
				// num *= (0 - x_j) = x_j  (since -x = x in GF(256))
				num = gf256Mul(num, xs[j])
				// den *= (x_i - x_j)
				den = gf256Mul(den, gf256Add(xs[i], xs[j]))
			}

			// l_i(0) = num / den
			lagrange := gf256Div(num, den)
			value = gf256Add(value, gf256Mul(yi, lagrange))
		}
		secret[byteIdx] = value
	}

	return secret, nil
}
