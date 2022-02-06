package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return pk, &pk.PublicKey, nil
}

// RSAPrivateKeyToBytes RSA private key to bytes
func RSAPrivateKeyToBytes(pk *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})
}

// RSAPublicKeyToBytes RSA public key to bytes
func RSAPublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}), nil
}

// RSAPrivateKeyFromBytes bytes to RSA private key
func RSAPrivateKeyFromBytes(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// RSAPublicKeyFromBytes bytes to RSA public key
func RSAPublicKeyFromBytes(pub []byte) (*rsa.PublicKey, error) {
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

// EncryptRSA encrypts data with RSA public key
func EncryptRSA(msg []byte, pub *rsa.PublicKey, label []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, pub, msg, label)
}

// DecryptRSA decrypts data with RSA private key
func DecryptRSA(msg []byte, pk *rsa.PrivateKey, label []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha512.New(), rand.Reader, pk, msg, label)
}

// GenerateECDSAKeyPair generates a new ECDSA key pair
func GenerateECDSAKeyPair(c elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	pk, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk, &pk.PublicKey, nil
}

// ECDSAPrivateKeyToBytes ECDSA private key to bytes
func ECDSAPrivateKeyToBytes(pk *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509Encoded,
	}), nil
}

// ECDSAPublicKeyToBytes ECDSA public key to bytes
func ECDSAPublicKeyToBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509Encoded,
	}), nil
}

// ECDSAPrivateKeyFromBytes bytes to ECDSA private key
func ECDSAPrivateKeyFromBytes(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	return x509.ParseECPrivateKey(block.Bytes)
}

// ECDSAPublicKeyFromBytes bytes to ECDSA public key
func ECDSAPublicKeyFromBytes(pub []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not valid ecdsa.PublicKey")
	}
	return key, nil
}

// EncryptAES encrypts data with AES key
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

// DecryptAES decrypts data with AES key
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
