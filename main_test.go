package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() *gin.Engine {
	r := gin.Default()
	return r
}

// Handle failure cases

func TestGenerateTimeBoundLicense(t *testing.T) {
	r := setupRouter()
	r.POST("/generate-license", GenerateLicense)

	license := LicenseRequest{
		Type:   "time-bound",
		Expiry: 7,
	}
	jsonBody, _ := json.Marshal(license)

	req, _ := http.NewRequest("POST", "/generate-license", bytes.NewBuffer(jsonBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	resp := License{}
	json.Unmarshal(responseData, &resp)

	assert.NotEmpty(t, resp.Key)
	assert.Equal(t, "time-bound", resp.Type)
	assert.Equal(t, time.Now().AddDate(0, 0, 7).Day(), resp.ExpiryDate.Day())

}
func TestGenerateUsageLimitedLicense(t *testing.T) {
	r := setupRouter()
	r.POST("/generate-license", GenerateLicense)

	license := LicenseRequest{
		Type:   "usage-limited",
		Expiry: 10,
	}
	jsonBody, _ := json.Marshal(license)

	req, _ := http.NewRequest("POST", "/generate-license", bytes.NewBuffer(jsonBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	resp := License{}
	json.Unmarshal(responseData, &resp)

	assert.NotEmpty(t, resp.Key)
	assert.Equal(t, "usage-limited", resp.Type)
	assert.Equal(t, 10, resp.TokensLeft)

}

func TestInvalidLicenseType(t *testing.T) {
	r := setupRouter()
	r.POST("/generate-license", GenerateLicense)

	license := LicenseRequest{
		Type:   "time",
		Expiry: 7,
	}
	jsonBody, _ := json.Marshal(license)

	req, _ := http.NewRequest("POST", "/generate-license", bytes.NewBuffer(jsonBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestInvalidLicenseExpiry(t *testing.T) {
	r := setupRouter()
	r.POST("/generate-license", GenerateLicense)

	license := LicenseRequest{
		Type:   "usage-limited",
		Expiry: -1,
	}
	jsonBody, _ := json.Marshal(license)

	req, _ := http.NewRequest("POST", "/generate-license", bytes.NewBuffer(jsonBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
}

func TestFetchLicense(t *testing.T) {
	r := setupRouter()
	r.GET("/fetch-license", GetLicense)

	req, _ := http.NewRequest("GET", "/fetch-license", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

}

func TestEncryptDecryption(t *testing.T) {

	r := setupRouter()
	r.POST("/generate-license", GenerateLicense)
	r.POST("/encrypt-file", EncryptFile)
	r.GET("/decrypt-file", DecryptFile)

	// GENERATE LICENSE
	license := LicenseRequest{
		Type:   "time-bound",
		Expiry: 7,
	}
	jsonBody, _ := json.Marshal(license)

	req, _ := http.NewRequest("POST", "/generate-license", bytes.NewBuffer(jsonBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	resp := License{}
	json.Unmarshal(responseData, &resp)

	// ENCRYPTION
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	err := writer.WriteField("licensekey", resp.Key.String())
	if err != nil {
		t.Fatalf("Failed to create Form field:%s", err.Error())
	}

	part, err := writer.CreateFormFile("file", "testfile.txt")
	if err != nil {
		t.Fatalf("Failed to create Form File:%s", err.Error())
	}
	content := []byte("Hello world")
	part.Write(content)
	writer.Close()

	req, _ = http.NewRequest("POST", "/encrypt-file", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	// DECRYPTION - /decrypt-file?licensekey=1b8f08f7-09c8-408a-8a3f-ac54255b31a5&filepath=fileInput.enc
	baseURL := fmt.Sprintf("/decrypt-file?licensekey=%v&filepath=%v", resp.Key, "testfile.enc")

	req, _ = http.NewRequest("GET", baseURL, nil)
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

}

func TestGenerateLink(t *testing.T) {
	r := setupRouter()
	r.POST("/generate-license", GenerateLicense)
	r.POST("/generate-link", GenerateSecureURL)

	// GENERATE LICENSE
	license := LicenseRequest{
		Type:   "usage-limited",
		Expiry: 6,
	}
	jsonBody, _ := json.Marshal(license)

	req, _ := http.NewRequest("POST", "/generate-license", bytes.NewBuffer(jsonBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	resp := License{}
	json.Unmarshal(responseData, &resp)

	// Generate secure shareable URL
	reqBody := URLRequest{LicenseKey: resp.Key.String(), FilePath: "testfile.enc"}
	jsonBody, _ = json.Marshal(reqBody)
	fmt.Print(string(jsonBody))

	req, _ = http.NewRequest("POST", "/generate-link", bytes.NewBuffer(jsonBody))
	w = httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Result().StatusCode)
}
