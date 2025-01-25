package main

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	_ "license-encryption-service/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var Licenses = make(map[uuid.UUID]License)
var File = make(map[string]uuid.UUID)
var LOG logrus.Logger

// @title Secure License Encryption Service
// @version 1.0
// @description Handles license generation, file encryption, and secure link creation.
// @host localhost:3000
func main() {

	LOG = *GetLogger()

	// routes
	router := gin.Default()
	router.GET("/sles/api/v1/fetch-license", GetLicense)
	router.POST("/sles/api/v1/generate-license", GenerateLicense)
	router.POST("/sles/api/v1/encrypt-file", EncryptFile)
	router.GET("/sles/api/v1/encrypt-file", GetEncryptedFiles)
	router.GET("/sles/api/v1/decrypt-file", DecryptFile)
	router.POST("/sles/api/v1/generate-link", GenerateSecureURL)
	router.GET("/sles/api/v1/secure-file", SecureFileAccess)
	// swagger
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Start server
	LOG.Info("Listening and serving on 3000")
	router.Run("localhost:3000")

}
