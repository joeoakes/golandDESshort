package main

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// Function to encrypt the data using DES algorithm
func encryptDES(key, text []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to include it at the beginning of the ciphertext.
	ciphertext := make([]byte, des.BlockSize+len(text))
	iv := ciphertext[:des.BlockSize]
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], text)

	return ciphertext, nil
}

// Function to decrypt the data using DES algorithm
func decryptDES(key, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be retrieved from the beginning of the ciphertext.
	iv := ciphertext[:des.BlockSize]
	ciphertext = ciphertext[des.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func main() {
	key := []byte("s3cr3t_k") // 8 bytes key for DES
	plaintext := []byte("Hello, World!")

	fmt.Printf("plaintext: %s\n", plaintext)

	// Encrypt the data
	encrypted, err := encryptDES(key, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted: %x\n", encrypted)

	// Decrypt the data
	decrypted, err := decryptDES(key, encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)
}
