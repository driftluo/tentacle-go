package secio

import (
	"strings"
)

// ECDHP256 is key agreement algorithm
const ECDHP256 = "P-256"

// ECDHP384 is key agreement algorithm
const ECDHP384 = "P-384"

// AES128GCM is aead encryption algorithm
const AES128GCM = "AES-128-GCM"

// AES256GCM is aead encryption algorithm
const AES256GCM = "AES-256-GCM"

// CHACHA20POLY1305 is aead encryption algorithm
const CHACHA20POLY1305 = "CHACHA20_POLY1305"

// SHA256 is hash algorithm
const SHA256 = "SHA256"

// SHA512 is hash algorithm
const SHA512 = "SHA512"

// DefaultAgreementsProposition is the default key agreement algorithm
const DefaultAgreementsProposition = "P-256,P-384"

// DefaultCiphersProposition is the default aead encryption algorithm
const DefaultCiphersProposition = "AES-128-GCM,AES-256-GCM,CHACHA20_POLY1305"

// DefaultDigestsProposition is the default hash algorithm used in handshake
const DefaultDigestsProposition = "SHA256,SHA512"

func selectPropose(order int, ours, theirs string) (string, error) {
	var f, s []string
	switch {
	case order < 0, order == 0:
		f = strings.Split(theirs, ",")
		s = strings.Split(ours, ",")
	case order > 0:
		f = strings.Split(ours, ",")
		s = strings.Split(theirs, ",")
	}

	for _, fc := range f {
		for _, sc := range s {
			if fc == sc {
				return fc, nil
			}
		}
	}

	return "", ErrNoCommonAlgorithms
}

func checkAgreements(s string) bool {
	ss := strings.Split(s, ",")

	for _, sss := range ss {
		switch sss {
		case ECDHP256, ECDHP384:
			continue
		default:
			return false
		}
	}

	return true
}

func checkCiphers(s string) bool {
	ss := strings.Split(s, ",")

	for _, sss := range ss {
		switch sss {
		case AES128GCM, AES256GCM, CHACHA20POLY1305:
			continue
		default:
			return false
		}
	}

	return true
}

func checkDigests(s string) bool {
	ss := strings.Split(s, ",")

	for _, sss := range ss {
		switch sss {
		case SHA256, SHA512:
			continue
		default:
			return false
		}
	}

	return true
}
