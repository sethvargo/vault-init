// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
)

var (
	vaultAddr     string
	s3BucketName  string
	httpClient    http.Client
	kmsKeyId      string

	vaultSecretShares      int
	vaultSecretThreshold   int
	vaultStoredShares      int
	vaultRecoveryShares    int
	vaultRecoveryThreshold int
)

// InitRequest holds a Vault init request.
type InitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
	StoredShares      int `json:"stored_shares"`
	RecoveryShares    int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

// UnsealRequest holds a Vault unseal request.
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse holds a Vault unseal response.
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

func main() {
	logrus.SetLevel(getLogLevel())
	logrus.SetFormatter(&logrus.JSONFormatter{})
        logrus.Info("Starting the vault-init service...")

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	vaultSecretShares = intFromEnv("VAULT_SECRET_SHARES", 5)
	vaultSecretThreshold = intFromEnv("VAULT_SECRET_THRESHOLD", 3)
	
	vaultInsecureSkipVerify := boolFromEnv("VAULT_SKIP_VERIFY", false)

	vaultAutoUnseal := boolFromEnv("VAULT_AUTO_UNSEAL", true)

	if vaultAutoUnseal {
		vaultStoredShares = intFromEnv("VAULT_STORED_SHARES", 1)
		vaultRecoveryShares = intFromEnv("VAULT_RECOVERY_SHARES", 1)
		vaultRecoveryThreshold = intFromEnv("VAULT_RECOVERY_THRESHOLD", 1)
	}

	checkInterval := durFromEnv("CHECK_INTERVAL", 10*time.Second)

	s3BucketName = os.Getenv("S3_BUCKET_NAME")
	if s3BucketName == "" {
		logrus.Fatal("S3_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		logrus.Fatal("KMS_KEY_ID must be set and not empty")
	}

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: vaultInsecureSkipVerify,
			},
		},
	}

	for {
		response, err := httpClient.Get(vaultAddr + "/v1/sys/health")
		if response != nil && response.Body != nil {
			response.Body.Close()
		}

		if err != nil {
			logrus.Error(err)
			time.Sleep(checkInterval)
			continue
		}

		switch response.StatusCode {
		case 200:
			logrus.Debug("Vault is initialized and unsealed.")
		case 429:
			logrus.Info("Vault is unsealed and in standby mode.")
		case 501:
			logrus.Info("Vault is not initialized.")
			logrus.Info("Initializing...")
			initialize()
			if !vaultAutoUnseal {
				logrus.Info("Unsealing...")
				unseal()
			}
		case 503:
			logrus.Info("Vault is sealed.")
			if !vaultAutoUnseal {
				logrus.Info("Unsealing...")
				unseal()
			}
		default:
			logrus.Warning("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		logrus.Debug("Next check in %s", checkInterval)
		time.Sleep(checkInterval)
	}
}

func initialize() {
	initRequest := InitRequest{
		SecretShares:      vaultSecretShares,
		SecretThreshold:   vaultSecretThreshold,
		StoredShares:      vaultStoredShares,
		RecoveryShares:    vaultRecoveryShares,
		RecoveryThreshold: vaultRecoveryThreshold,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		logrus.Error(err)
		return
	}

	r := bytes.NewReader(initRequestData)

	request, err := http.NewRequest("PUT", vaultAddr+"/v1/sys/init", r)
	if err != nil {
		logrus.Error(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		logrus.Error(err)
		return
	}

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logrus.Error(err)
		return
	}

	if response.StatusCode != 200 {
		logrus.Error("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		logrus.Error(err)
		return
	}

	logrus.Info("Encrypting unseal keys and the root token and uploading to bucket...")

	AWSSession, err := session.NewSession()
	if err != nil {
		logrus.Error("Error creating session: ", err)
	}

	KMSService := kms.New(AWSSession)
	S3Service := s3.New(AWSSession)

	// Encrypt root token.
	rootTokenEncryptedData, err := KMSService.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: []byte(initResponse.RootToken),
	})
	if err != nil {
		logrus.Error("Error encrypting root token: ", err)
	}

	// Encrypt unseal keys.
	unsealKeysEncryptedData, err := KMSService.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: []byte(base64.StdEncoding.EncodeToString(initRequestResponseBody)),
	})
	if err != nil {
		logrus.Error("Error encrypting unseal keys: ", err)
	}

	// Save the encrypted root token.
	rootTokenPutRequest := &s3.PutObjectInput{
		Body:   bytes.NewReader(rootTokenEncryptedData.CiphertextBlob),
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("root-token.json.enc"),
	}

	_, err = S3Service.PutObject(rootTokenPutRequest)
	if err != nil {
		logrus.Error("Cannot write root token to bucket s3://%s/%s: %s", s3BucketName, "root-token.json.enc", err)
	} else {
		logrus.Info("Root token written to s3://%s/%s", s3BucketName, "root-token.json.enc")
	}

	// Save the encrypted unseal keys.
	unsealKeysEncryptRequest := &s3.PutObjectInput{
		Body:   bytes.NewReader(unsealKeysEncryptedData.CiphertextBlob),
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("unseal-keys.json.enc"),
	}

	_, err = S3Service.PutObject(unsealKeysEncryptRequest)
	if err != nil {
		logrus.Error("Cannot write unseal keys to bucket s3://%s/%s: %s", s3BucketName, "unseal-keys.json.enc", err)
	} else {
		logrus.Info("Unseal keys written to s3://%s/%s", s3BucketName, "unseal-keys.json.enc")
	}

	logrus.Info("Initialization complete.")
}

func unseal() {

	AWSSession, err := session.NewSession()
	if err != nil {
		logrus.Error("Error creating session: ", err)
	}

	KMSService := kms.New(AWSSession)
	S3Service := s3.New(AWSSession)

	unsealKeysRequest := &s3.GetObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("unseal-keys.json.enc"),
	}

	unsealKeysEncryptedObject, err := S3Service.GetObject(unsealKeysRequest)
	if err != nil {
		logrus.Error(err)
		return
	}

	unsealKeysEncryptedObjectData, err := ioutil.ReadAll(unsealKeysEncryptedObject.Body)
	if err != nil {
		logrus.Error(err)
	}

	unsealKeysData, err := KMSService.Decrypt(&kms.DecryptInput{
		CiphertextBlob: unsealKeysEncryptedObjectData,
	})
	if err != nil {
		logrus.Error(err)
		return
	}

	var initResponse InitResponse

	unsealKeysPlaintext, err := base64.StdEncoding.DecodeString(string(unsealKeysData.Plaintext))
	if err != nil {
		logrus.Error(err)
		return
	}

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
		logrus.Error(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(key)
		if done {
			return
		}

		if err != nil {
			logrus.Error(err)
			return
		}
	}
}

func unsealOne(key string) (bool, error) {
	unsealRequest := UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := http.NewRequest(http.MethodPut, vaultAddr+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("unseal: non-200 status code: %d", response.StatusCode)
	}

	unsealRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}

func getLogLevel() logrus.Level {
	levelString, exists := os.LookupEnv("LOG_LEVEL")
	if !exists {
		return logrus.InfoLevel
	}

	level, err := logrus.ParseLevel(levelString)
	if err != nil {
		logrus.Errorf("error parsing LOG_LEVEL: %v", err)
		return logrus.InfoLevel
	}

	return level
}

func boolFromEnv(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		logrus.Fatalf("failed to parse %q: %s", env, err)
	}
	return b
}

func intFromEnv(env string, def int) int {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		logrus.Fatalf("failed to parse %q: %s", env, err)
	}
	return i
}

func durFromEnv(env string, def time.Duration) time.Duration {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	r := val[len(val)-1]
	if r >= '0' || r <= '9' {
		val = val + "s" // assume seconds
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		logrus.Fatalf("failed to parse %q: %s", env, err)
	}
	return d
}
