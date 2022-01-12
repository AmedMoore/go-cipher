package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return pk, &pk.PublicKey, nil
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(pk *rsa.PrivateKey) []byte {
	b := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		},
	)
	return b
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not valid rsa.PublicKey")
	}
	return key, nil
}

// EncryptRSA encrypts data with public key
func EncryptRSA(msg []byte, pub *rsa.PublicKey, label []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, pub, msg, label)
}

// DecryptRSA decrypts data with private key
func DecryptRSA(msg []byte, pk *rsa.PrivateKey, label []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha512.New(), rand.Reader, pk, msg, label)
}

// EncryptAES encrypts data with a key
func EncryptAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ci := make([]byte, aes.BlockSize+len(data))
	iv := ci[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ci[aes.BlockSize:], data)

	return ci, nil
}

// DecryptAES decrypts data with a key
func DecryptAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	enc := append([]byte{}, data...)

	if len(enc) < aes.BlockSize {
		return nil, errors.New("ciphertext block size is too short")
	}

	iv := enc[:aes.BlockSize]
	enc = enc[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(enc, enc)

	return enc, nil
}
