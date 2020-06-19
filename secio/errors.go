package secio

import "errors"

// ErrConnectSelf means node handshake with self
var ErrConnectSelf = errors.New("ConnectSelf")

// ErrNoCommonAlgorithms means can't find same propose algorithms
var ErrNoCommonAlgorithms = errors.New("No algorithms in common")

// ErrInvalidData means unable to parse remote's data
var ErrInvalidData = errors.New("Invalid data")

// ErrEphemeralKeyGenerationFailed means failed to generate ephemeral key
var ErrEphemeralKeyGenerationFailed = errors.New("Failed to generate ephemeral key")

// ErrVerificationFail means handshake verification failure
var ErrVerificationFail = errors.New("Failed Verification signature")

// ErrSecretGenerationFailed means failed to generate the secret shared key
var ErrSecretGenerationFailed = errors.New("Failed to generate the secret shared key from the ephemeral key")

// ErrFrameTooShort means frame is wrong
var ErrFrameTooShort = errors.New("short packet")

// ErrDecipherFail means failure to decode remote data
var ErrDecipherFail = errors.New("Can not decipher remote data")
