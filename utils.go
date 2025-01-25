package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"mime/multipart"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const TIME_BOUND = "time-bound"
const USAGE_LIMITED = "usage-limited"
const OUTPUTDIR = "./encrypted_files"

type License struct {
	Key        uuid.UUID `json:"key"`
	Type       string    `json:"type"`
	ExpiryDate time.Time `json:""expiryDate"`
	TokensLeft int       `json:""tokensLeft"`
}

type LicenseRequest struct {
	Type   string `json:"type" binding:"required"`
	Expiry int    `json:"expiry" binding:"required"`
}

type FormRequest struct {
	File       *multipart.FileHeader `form:"file" binding:"required"`
	LicenseKey string                `form:"licensekey" binding:"required"`
}

type URLRequest struct {
	FilePath   string `json:"filepath" binding:"required"`
	LicenseKey string `json:"licensekey" binding:"required"`
}

func GetLogger() *logrus.Logger {

	Log := logrus.New()
	Log.SetFormatter(&logrus.JSONFormatter{})

	return Log
}

func ValidateLicenseKey(key uuid.UUID) (License, error) {

	var licenseData License

	licenseData, exists := Licenses[key]
	if !exists {

		return licenseData, errors.New("License key doesn't exist")
	}

	if licenseData.Type == TIME_BOUND && (licenseData.ExpiryDate.Sub(time.Now()) < 0) {

		return licenseData, errors.New("License key expired")
	}

	if licenseData.Type == USAGE_LIMITED && (licenseData.TokensLeft <= 0) {

		return licenseData, errors.New("License key expired")
	}

	return licenseData, nil

}

func AESDecryption(key uuid.UUID, srcFile *os.File, destFile *os.File) error {

	// Generate a random initialization vector(iv)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Read iv from encrypted file.
	if _, err := srcFile.Read(iv); err != nil {
		return err
	}

	// Hash UUID using SHA-256 to get a 32-byte AES key
	hash := sha256.New()
	hash.Write(key[:]) // Write the 16-byte UUID
	decKey := hash.Sum(nil)

	// Generate a new cipher with key(UUID)
	cipherBlock, err := aes.NewCipher(decKey[:])
	if err != nil {
		return err
	}

	// Create CBC Decrypter using the cipherBlock(created with uuid as key)
	blockMode := cipher.NewCBCDecrypter(cipherBlock, iv)

	// Buffer for reading the input file in blocks
	blockSize := cipherBlock.BlockSize()
	buffer := make([]byte, blockSize)

	for {
		num_bytes_read, err := srcFile.Read(buffer)
		if err == io.EOF {
			// Reached end of the file. decryption completed
			break
		}
		if err != nil {
			return err
		}

		// If the last block size is less than blocksize, we need to do padding.
		// As encrypter needs complete blocksize for enecryption
		if num_bytes_read < blockSize {
			buffer = append(buffer[:num_bytes_read], make([]byte, blockSize-num_bytes_read)...)
		}

		//Encrypt the current chunk of data
		blockMode.CryptBlocks(buffer, buffer)

		// write encrypted data to file
		if _, err := destFile.Write(buffer); err != nil {
			return err
		}
	}
	return nil

}

func AESEncryption(key uuid.UUID, srcFile multipart.File, destFile *os.File) error {

	// Generate a random initialization vector(iv)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Write iv to output file. used while decrypting
	if _, err := destFile.Write(iv); err != nil {
		return err
	}

	// Hash UUID using SHA-256 to get a 32-byte AES key
	hash := sha256.New()
	hash.Write(key[:]) // Write the 16-byte UUID
	encKey := hash.Sum(nil)

	// Generate a new cipher with key(UUID)
	cipherBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}

	// Create CBC Encrypter using the cipherBlock(created with uuid as key)
	blockMode := cipher.NewCBCEncrypter(cipherBlock, iv)

	// Buffer for reading the input file in blocks
	blockSize := cipherBlock.BlockSize()
	buffer := make([]byte, blockSize)

	for {
		num_bytes_read, err := srcFile.Read(buffer)
		if err == io.EOF {
			// Reached end of the file. encryption completed
			break
		}
		if err != nil {
			return err
		}

		// If the last block size is less than blocksize, we need to do padding.
		// As encrypter needs complete blocksize for enecryption
		if num_bytes_read < blockSize {
			buffer = append(buffer[:num_bytes_read], make([]byte, blockSize-num_bytes_read)...)
		}

		//Encrypt the current chunk of data
		blockMode.CryptBlocks(buffer, buffer)

		// write encrypted data to file
		if _, err := destFile.Write(buffer); err != nil {
			return err
		}
	}
	return nil
}
