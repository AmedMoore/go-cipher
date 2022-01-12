package cipher

import (
	"bytes"
	"crypto/rand"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"os"
	"testing"
)

// Test_RSA_AES_Hybrid_Encryption uses RSA and AES
// to perform hybrid-encryption to encrypt/decrypt
// image file.
//
// This technique can be used in real-world scenario
// to transfer data between server-client securely.
func Test_RSA_AES_Hybrid_Encryption(t *testing.T) {
	// create build dir if not exists
	err := os.MkdirAll("build", os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	// create new img
	w, h := 8192, 8192
	img := image.NewRGBA(image.Rectangle{
		Min: image.Point{}, Max: image.Point{X: w, Y: h},
	})

	// set color for each pixel
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			c := color.White
			if x%2 == 0 || y%2 == 0 {
				c = color.Black
			}
			img.Set(x, y, c)
		}
	}

	// write img to fs
	imgFile, _ := os.Create("build/src.png")
	if err = png.Encode(imgFile, img); err != nil {
		t.Fatal(err)
	}

	// read img as bytes
	src, err := ioutil.ReadFile("build/src.png")
	if err != nil {
		t.Fatal(err)
	}

	// close the img file
	if err = imgFile.Close(); err != nil {
		t.Fatal(err)
	}

	//
	// 1) Create an RSA key pair.
	// this usually done by the recipient (aka server).
	//

	pvtKey, pubKey, err := GenerateKeyPair(4096)
	if err != nil {
		t.Fatal(err)
	}

	// write the pvt key to fs for testing purposes
	pvtData := PrivateKeyToBytes(pvtKey)
	err = ioutil.WriteFile("build/pvt.pem", pvtData, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	// write the pub key to fs for testing purposes
	pubData, err := PublicKeyToBytes(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile("build/pub.pem", pubData, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	//
	// 2) Generate a random AES256 key.
	// this usually done by the sender (aka client).
	//

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	// write the plain AES key to fs for testing purposes
	err = ioutil.WriteFile("build/aes.key", key, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	//
	// 3) Encrypt the image with the AES key.
	//

	encImg, err := EncryptAES(key, src)
	if err != nil {
		t.Fatal(err)
	}

	// write the encrypted image to fs for testing purposes
	err = ioutil.WriteFile("build/img.encrypted", encImg, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	//
	// 4) Encrypt the AES key with the RSA public key.
	//

	encKey, err := EncryptRSA(key, pubKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	// write the encrypted AES key to fs for testing purposes
	err = ioutil.WriteFile("build/aes.key.encrypted", encKey, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	//
	// 5) Use the RSA private key to decrypt the AES key.
	//

	decKey, err := DecryptRSA(encKey, pvtKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	// write the decrypted AES key to fs for testing purposes
	err = ioutil.WriteFile("build/aes.key.decrypted", decKey, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	//
	// 6) Decrypt the image with the decrypted key.
	//

	decImg, err := DecryptAES(decKey, encImg)
	if err != nil {
		t.Fatal(err)
	}

	// write the decrypted image to fs for testing purposes
	decImgDec, _, err := image.Decode(bytes.NewReader(decImg))
	if err != nil {
		t.Fatal(err)
	}
	decImgFile, _ := os.Create("build/img.decrypted.png")
	if err = png.Encode(decImgFile, decImgDec); err != nil {
		t.Fatal(err)
	}

	// close the decrypted img file
	if err = decImgFile.Close(); err != nil {
		t.Fatal(err)
	}
}
