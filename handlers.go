package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// @Summary Fetch the license keys
// @Description Get the list of license keys
// @Accept json
// @Produce json
// @Success 200
// @Router /sles/api/v1/fetch-license [get]
func GetLicense(c *gin.Context) {
	LOG.Info("Fetched licenses successfully")
	c.IndentedJSON(http.StatusOK, Licenses)

}

// @Summary Get the list of encrypted files with it's associated keys
// @Description Get the list of encrypted files
// @Accept json
// @Produce json
// @Success 200
// @Router /sles/api/v1/encrypt-file [get]
func GetEncryptedFiles(c *gin.Context) {
	LOG.Info("Fetched encrypted files successfully")
	c.IndentedJSON(http.StatusOK, File)

}

// @Summary Generate license key
// @Description Create a new license key by providing a valid license type and expiry (e.g., days, num of tokens).
// @Accept json
// @Param Request body LicenseRequest true "License details. Specify 'type' as 'time-bound' or 'usage-limited'. For 'expiry', provide either days (e.g., 30) or tokens (e.g., 20)."
// @Produce json
// @Success 201
// @Router /sles/api/v1/generate-license [post]
func GenerateLicense(c *gin.Context) {
	var reqBody LicenseRequest
	var newLicense License

	if err := c.BindJSON(&reqBody); err != nil {
		LOG.Error("Unable to parse request body. Error: ", err.Error())
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "Unable to parse request body"})

	}

	licenseType := strings.ToLower(reqBody.Type)

	if licenseType != TIME_BOUND && licenseType != USAGE_LIMITED {
		LOG.Error("Unsupported license type. Provided type: ", licenseType)
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Unsupported license type. Specify 'type' as 'time-bound' or 'usage-limited'"})
	}

	if reqBody.Expiry <= 0 {
		LOG.Error("Invalid expiry. please provide positive numbers")
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Invalid expiry. Please provide either days (e.g., 30) or tokens (e.g., 20)"})
	}

	newLicense = License{}
	newLicense.Key = uuid.New()
	newLicense.Type = licenseType
	if licenseType == TIME_BOUND {
		newLicense.ExpiryDate = time.Now().AddDate(0, 0, reqBody.Expiry)
	} else {
		newLicense.TokensLeft = reqBody.Expiry
	}

	Licenses[newLicense.Key] = newLicense

	LOG.Info("License key generated successfully")
	c.IndentedJSON(http.StatusCreated, newLicense)

}

// @Summary Encrypt the file
// @Description Encrypt the file using the provided license key.
// @Accept multipart/form-data
// @Param file formData file true "File to be uploaded"
// @Param licensekey formData string true "License key"
// @Produce application/octet-stream
// @Success 200 {file} file "Encrypted file"
// @Router /sles/api/v1/encrypt-file [post]
func EncryptFile(c *gin.Context) {
	var reqForm FormRequest
	var key uuid.UUID
	var err error
	var licenseData License

	if err := c.ShouldBind(&reqForm); err != nil {
		LOG.Error("Couldn't parse request. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Couldn't parse request.", "error": err.Error()})

	}
	fmt.Println(reqForm)
	if key, err = uuid.Parse(reqForm.LicenseKey); err != nil {
		LOG.Error("Couldn't parse license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Couldn't parse license key.", "error": err.Error()})

	}

	// Validate the license
	if licenseData, err = ValidateLicenseKey(key); err != nil {
		LOG.Error("Failed to validate license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusForbidden, gin.H{"message": err.Error()})

	}

	srcFile, err := reqForm.File.Open()
	if err != nil {
		LOG.Error("unable to parse the file. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "unable to parse the file", "error": err.Error()})

	}

	FileName := strings.TrimSuffix(reqForm.File.Filename, filepath.Ext(reqForm.File.Filename)) + ".enc"
	encryptedFileName := filepath.Join(OUTPUTDIR, FileName)

	// Create file to save encrypted data
	destFile, err := os.Create(encryptedFileName)
	if err != nil {
		LOG.Error("unable to create the dest file. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "unable to create the dest file", "error": err.Error()})

	}

	if err = AESEncryption(key, srcFile, destFile); err != nil {
		LOG.Error("Error occurred while encrypting file. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Error occurred while encrypting file", "error": err.Error()})

	}

	// If it's usage bases, update the tokens
	if licenseData.Type == USAGE_LIMITED {
		licenseData.TokensLeft -= 1
		Licenses[key] = licenseData
	}

	File[FileName] = key

	c.FileAttachment(encryptedFileName, FileName)

	defer srcFile.Close()
	defer destFile.Close()

}

// @Summary Generate secure URL
// @Description Create a secure, shareable link to access the decrypted file.
// @Accept json
// @Produce json
// @Param URLRequest body URLRequest true "encrypted file path and license key for generating shareable URL"
// @Sucess 200
// @Router /sles/api/v1/generate-link [post]
func GenerateSecureURL(c *gin.Context) {
	var reqBody URLRequest
	var err error
	var key uuid.UUID

	if err = c.ShouldBindJSON(&reqBody); err != nil {
		LOG.Error("Unable to parse request body. Error: ", err.Error())
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": "Unable to parse request body"})

	}

	licenseKey := reqBody.LicenseKey
	filePath := reqBody.FilePath

	if licenseKey == "" || filePath == "" {
		LOG.Error("Mandatory fields are not present. licensekey, filepath are required")
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Mandatory fields are not present. licensekey, filepath are required"})

	}

	if key, err = uuid.Parse(licenseKey); err != nil {
		LOG.Error("Couldn't parse license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Couldn't parse license key.", "error": err.Error()})

	}

	// Validate the license
	if _, err := ValidateLicenseKey(key); err != nil {

		LOG.Error("Invalid License key. Error: ", err.Error())
		c.IndentedJSON(http.StatusForbidden, gin.H{"message": err.Error()})

	}

	expiry := time.Now().Add(time.Hour * 1).Unix()
	URL := fmt.Sprintf("http://localhost:3000/sles/api/v1/secure-file?licensekey=%v&filepath=%v&expires=%d", licenseKey, filePath, expiry)

	LOG.Info("secure link generated successfully")
	c.IndentedJSON(http.StatusCreated, gin.H{"message": "secure link generated successfully", "URL": URL})

}

// @ignore
// Summary Decrypt the file
// @Description File decryption using the specified license key
// @Accept json
// @Produce application/octet-stream
// @Param filepath query string true "encrypted file path"
// @Param licensekey query string true "license key for decryption"
// @Success 200 {file} file "Encrypted file"

func DecryptFile(c *gin.Context) {
	var err error
	var key uuid.UUID
	var licenseData License

	licenseKey := c.Query("licensekey")
	filePath := c.Query("filepath")

	if licenseKey == "" || filePath == "" {
		LOG.Error("Mandatory fields are not present. licensekey, filepath are required")
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "licensekey, filepath are required"})

	}

	if key, err = uuid.Parse(licenseKey); err != nil {
		LOG.Error("Couldn't parse license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Couldn't parse license key.", "error": err.Error()})

	}

	// Validate the license
	if licenseData, err = ValidateLicenseKey(key); err != nil {
		LOG.Error("Invalid license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusForbidden, gin.H{"message": err.Error()})

	}

	if File[filePath] != key {
		LOG.Error("Invalid license key. The provided key cannot be used to decrypt this file. Error: ")
		c.IndentedJSON(http.StatusForbidden, gin.H{"message": "Incorrect key"})

	}

	FileName := strings.TrimSuffix(filePath, filepath.Ext(filePath)) + ".dec"
	decryptedFileName := filepath.Join(OUTPUTDIR, FileName)

	srcFile, err := os.Open(filepath.Join(OUTPUTDIR, filePath))
	if err != nil {
		LOG.Error("Unable to open the encrypted file. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "unable to open the encrypted file", "error": err.Error()})

	}

	// Create file to save encrypted data
	destFile, err := os.Create(decryptedFileName)
	if err != nil {
		LOG.Error("Unable to create the decryption file. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "unable to create the decryption file", "error": err.Error()})

	}

	if err = AESDecryption(key, srcFile, destFile); err != nil {
		LOG.Error("Error occurred while decrypting the file. Error:", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Error occurred while decrypting file", "error": err.Error()})

	}

	// If it's usage bases, update the tokens
	if licenseData.Type == USAGE_LIMITED {
		licenseData.TokensLeft -= 1
		Licenses[key] = licenseData
	}

	c.FileAttachment(decryptedFileName, FileName)

	defer srcFile.Close()
	defer destFile.Close()

}

// @ignore
// Summary Secure file access
// @Description Validates the provided link. If the link is valid, it returns the decrypted file.
// @Accept json
// @Param filepath query string true "encrypted file path"
// @Param licensekey query string true "license key for decryption"
// @Param expires query string true "Time of expiry"
// @Success 302 {string} string "Redirecting to new URL"

func SecureFileAccess(c *gin.Context) {
	var key uuid.UUID
	var err error

	licenseKey := c.Query("licensekey")
	filePath := c.Query("filepath")
	expires := c.Query("expires")

	if licenseKey == "" || filePath == "" || expires == "" {
		LOG.Error("Mandatory fields are not present. licensekey, filepath, expires are required")
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Mandatory fields are not present. licensekey, filepath, expires are required"})

	}

	// Check link expiry time
	expirationTime, err := strconv.ParseInt(expires, 10, 64)
	if err != nil {
		LOG.Error("Couldn't parse timestamp. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Couldn't parse timestamp.", "error": err.Error()})

	}

	if time.Now().Unix() > expirationTime {
		LOG.Error("Link Expired.")
		c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": "Link Expired. Please request new one."})

	}

	// validate licensekey -- it can be tampered. so check once
	if key, err = uuid.Parse(licenseKey); err != nil {
		LOG.Error("Couldn't parse license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": "Couldn't parse license key.", "error": err.Error()})

	}

	// Validate the license
	if _, err := ValidateLicenseKey(key); err != nil {
		LOG.Error("Invalid license key. Error: ", err.Error())
		c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": err.Error()})

	}

	redirectURL := fmt.Sprintf("http://localhost:3000/sles/api/v1/decrypt-file?licensekey=%v&filepath=%v", licenseKey, filePath)
	c.Redirect(http.StatusFound, redirectURL)

}
