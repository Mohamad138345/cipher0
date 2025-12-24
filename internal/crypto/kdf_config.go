// Package crypto provides cryptographic operations for the password manager.
package crypto

// KDFParams contains the parameters for the key derivation function.
type KDFParams struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// KDFConfig contains the KDF algorithm and its parameters.
// This is stored in the vault to ensure backward compatibility when
// the algorithm or parameters are changed in future versions.
type KDFConfig struct {
	Algorithm string    `json:"algorithm"`
	Params    KDFParams `json:"params"`
}
