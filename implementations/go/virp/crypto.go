// Copyright (c) 2026 Third Level IT LLC. All rights reserved.
// VIRP -- Verified Infrastructure Response Protocol
// Cryptographic operations -- HMAC-SHA256 signing and verification
//
// Key separation is STRUCTURAL:
//   - O-Keys sign Observation Channel messages ONLY
//   - R-Keys sign Intent Channel messages ONLY

package virp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"os"
)

// KeyType identifies the purpose of a signing key.
type KeyType uint8

const (
	KeyTypeOKey  KeyType = 1 // Observation key -- signs OC messages
	KeyTypeRKey  KeyType = 2 // Reasoning key -- signs IC messages
	KeyTypeChain KeyType = 3 // Chain key -- signs trust chain entries
)

// SigningKey holds a 256-bit HMAC key bound to a specific type.
type SigningKey struct {
	Key         [KeySize]byte
	Type        KeyType
	Fingerprint [HMACSize]byte
	Loaded      bool
}

// KeyInit initializes a signing key from raw bytes.
func KeyInit(keyType KeyType, keyBytes [KeySize]byte) *SigningKey {
	sk := &SigningKey{
		Key:    keyBytes,
		Type:   keyType,
		Loaded: true,
	}
	fp := sha256.Sum256(keyBytes[:])
	sk.Fingerprint = fp
	return sk
}

// KeyGenerate creates a random signing key from /dev/urandom.
func KeyGenerate(keyType KeyType) (*SigningKey, error) {
	var keyBytes [KeySize]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return nil, ErrKeyNotLoaded
	}
	return KeyInit(keyType, keyBytes), nil
}

// KeyLoadFile loads a 32-byte raw binary key from a file.
func KeyLoadFile(keyType KeyType, path string) (*SigningKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrKeyNotLoaded
	}
	if len(data) != KeySize {
		return nil, ErrKeyNotLoaded
	}
	var keyBytes [KeySize]byte
	copy(keyBytes[:], data)
	return KeyInit(keyType, keyBytes), nil
}

// KeySaveFile writes a 32-byte raw binary key to a file with 0600 permissions.
func KeySaveFile(sk *SigningKey, path string) error {
	if sk == nil || !sk.Loaded {
		return ErrKeyNotLoaded
	}
	return os.WriteFile(path, sk.Key[:], 0600)
}

// KeyDestroy zeros out a key in memory.
func KeyDestroy(sk *SigningKey) {
	if sk == nil {
		return
	}
	for i := range sk.Key {
		sk.Key[i] = 0
	}
	for i := range sk.Fingerprint {
		sk.Fingerprint[i] = 0
	}
	sk.Loaded = false
}

// HMACSHA256 computes HMAC-SHA256 over arbitrary data.
func HMACSHA256(key [KeySize]byte, data []byte) [HMACSize]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(data)
	var out [HMACSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// checkChannelKeyBinding enforces the structural channel-key boundary.
func checkChannelKeyBinding(channel uint8, keyType KeyType) error {
	if channel == ChannelOC && keyType != KeyTypeOKey {
		return ErrChannelViolation
	}
	if channel == ChannelIC && keyType != KeyTypeRKey {
		return ErrChannelViolation
	}
	return nil
}

// Sign computes and writes the HMAC-SHA256 into a serialized VIRP message.
// The HMAC covers bytes [0..23] + bytes [56..end], excluding the HMAC field
// at offsets [24..55]. This matches the C implementation exactly.
func Sign(msg []byte, sk *SigningKey) error {
	if sk == nil || !sk.Loaded {
		return ErrKeyNotLoaded
	}
	if len(msg) < HeaderSize {
		return ErrBufferTooSmall
	}

	// Channel is at offset 8
	channel := msg[8]
	if err := checkChannelKeyBinding(channel, sk.Type); err != nil {
		return err
	}

	// HMAC offset is 24 (after version(1) + type(1) + length(2) + node_id(4) +
	// channel(1) + tier(1) + reserved(2) + seq_num(4) + timestamp_ns(8) = 24)
	const hmacOffset = 24
	preHMAC := msg[:hmacOffset]
	postHMACStart := hmacOffset + HMACSize // 56
	var postHMAC []byte
	if len(msg) > postHMACStart {
		postHMAC = msg[postHMACStart:]
	}

	// Build signing buffer: pre-HMAC header + post-HMAC (payload)
	signBuf := make([]byte, 0, len(preHMAC)+len(postHMAC))
	signBuf = append(signBuf, preHMAC...)
	signBuf = append(signBuf, postHMAC...)

	computed := HMACSHA256(sk.Key, signBuf)
	copy(msg[hmacOffset:hmacOffset+HMACSize], computed[:])
	return nil
}

// Verify checks a VIRP message's HMAC-SHA256 signature.
// Uses constant-time comparison to prevent timing attacks.
func Verify(msg []byte, sk *SigningKey) error {
	if sk == nil || !sk.Loaded {
		return ErrKeyNotLoaded
	}
	if len(msg) < HeaderSize {
		return ErrBufferTooSmall
	}

	channel := msg[8]
	if err := checkChannelKeyBinding(channel, sk.Type); err != nil {
		return err
	}

	const hmacOffset = 24
	preHMAC := msg[:hmacOffset]
	postHMACStart := hmacOffset + HMACSize
	var postHMAC []byte
	if len(msg) > postHMACStart {
		postHMAC = msg[postHMACStart:]
	}

	signBuf := make([]byte, 0, len(preHMAC)+len(postHMAC))
	signBuf = append(signBuf, preHMAC...)
	signBuf = append(signBuf, postHMAC...)

	expected := HMACSHA256(sk.Key, signBuf)
	actual := msg[hmacOffset : hmacOffset+HMACSize]

	if subtle.ConstantTimeCompare(actual, expected[:]) != 1 {
		return ErrHMACFailed
	}
	return nil
}
