package hasher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func Encrypt(plainText, key string) (string, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", errors.New("ключ должен быть длиной 32 байта")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(cipherText, key string) (string, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", errors.New("ключ должен быть длиной 32 байта")
	}

	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("зашифрованный текст слишком короткий")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
