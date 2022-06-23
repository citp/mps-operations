package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// #############################################################################

func getCipher(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	Panic(err)
	AES_GCM, err := cipher.NewGCM(block)
	Panic(err)
	return AES_GCM
}

func getNonce(key []byte) []byte {
	return SHA256(key)[:12] // GCM requires a 12 byte nonce
}

func encrypt(pt []byte, key []byte) []byte {
	AES_GCM := getCipher(key)
	nonce := getNonce(key)
	return AES_GCM.Seal(nil, nonce, pt, nil)
}

func decrypt(ct []byte, key []byte) ([]byte, error) {
	AES_GCM := getCipher(key)
	nonce := getNonce(key)
	return AES_GCM.Open(nil, nonce, ct, nil)
}

// #############################################################################

func AEAD_Encrypt(pt []byte, key []byte) []byte {
	return encrypt(pt, key)
}

func AEAD_Decrypt(ct []byte, key []byte) ([]byte, error) {
	return decrypt(ct, key)
}
