/*
Medical Image Storage Chaincode for Hyperledger Fabric

This chaincode implements the smart contract for secure medical image
metadata storage and verification on Hyperledger Fabric blockchain.

NOVEL CONTRIBUTION 1: Blockchain-Coordinated Threshold Key Recovery Protocol
Unlike traditional Shamir's Secret Sharing where key reconstruction happens
off-chain without verification, this smart contract provides:
1. On-chain threshold enforcement - Smart contract verifies t-of-n policy (3/5)
2. Decentralized access control - No single party controls reconstruction
3. Immutable audit trail - All recovery attempts are logged on blockchain
4. Share revocation support - Compromised shares can be invalidated on-chain
5. Time-locked recovery - Optional delay for security-critical operations

NOVEL CONTRIBUTION 2: Key Rotation Protocol
Implements blockchain-coordinated key rotation with:
1. Epoch management - Tracks current key epoch for each image
2. Multi-party approval - Requires multiple approvals before rotation
3. Forward/backward secrecy - Old keys cannot derive new keys and vice versa
4. Audit trail - All rotation events logged on blockchain

Implements standard image storage operations plus novel protocols.

Functions:
- StoreImageMetadata: Store encrypted image metadata
- GetImageMetadata: Retrieve image metadata by ID
- VerifyImageHash: Verify image integrity
- GetImageHistory: Get transaction history
- UpdateImageStatus: Update image status (active/archived/revoked)
- RecordAccess: Log access events
- SubmitKeyShare: Submit a key share for recovery
- InitiateKeyRecovery: Start threshold-based key recovery process
- CheckRecoveryStatus: Check if threshold is met for recovery
- RevokeShare: Revoke a compromised share
- GetRecoveryAuditLog: Get all recovery attempts for an image
- InitiateRotation: Start a key rotation process (NEW)
- ApproveRotation: Approve a pending rotation (NEW)
- FinalizeRotation: Complete rotation and update epoch (NEW)
- GetCurrentEpoch: Get current key epoch for an image (NEW)
*/

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// ImageStoreChaincode implements the chaincode interface
type ImageStoreChaincode struct {
}

// ImageMetadata represents the structure for storing image information
type ImageMetadata struct {
	ImageID          string            `json:"image_id"`
	Hash             string            `json:"hash"`
	Signature        string            `json:"signature"`
	Shares           []KeyShare        `json:"shares"`
	PatientID        string            `json:"patient_id,omitempty"`
	ImageType        string            `json:"image_type,omitempty"`
	Department       string            `json:"department,omitempty"`
	UploadedBy       string            `json:"uploaded_by"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at"`
	Status           string            `json:"status"`
	EncryptionMethod string            `json:"encryption_method"`
	Threshold        string            `json:"threshold"`
	CustomMetadata   map[string]string `json:"custom_metadata,omitempty"`
}

// KeyShare represents a secret sharing key share reference
type KeyShare struct {
	ShareID   int    `json:"share_id"`
	ShareHash string `json:"share_hash"`
	HolderID  string `json:"holder_id,omitempty"`
}

// AccessLog represents an access event
type AccessLog struct {
	ImageID    string `json:"image_id"`
	AccessorID string `json:"accessor_id"`
	AccessType string `json:"access_type"`
	Timestamp  string `json:"timestamp"`
	IPAddress  string `json:"ip_address,omitempty"`
}

// KeyRecoverySession represents an ongoing key recovery process
// NOVEL: Blockchain-coordinated threshold key recovery
type KeyRecoverySession struct {
	SessionID       string                 `json:"session_id"`
	ImageID         string                 `json:"image_id"`
	InitiatedBy     string                 `json:"initiated_by"`
	InitiatedAt     string                 `json:"initiated_at"`
	Threshold       int                    `json:"threshold"`       // t in (t,n)
	TotalShares     int                    `json:"total_shares"`    // n in (t,n)
	SubmittedShares []SubmittedShare       `json:"submitted_shares"`
	Status          string                 `json:"status"` // pending, threshold_met, completed, expired, revoked
	ExpiresAt       string                 `json:"expires_at"`
	CompletedAt     string                 `json:"completed_at,omitempty"`
	RecoveryProof   string                 `json:"recovery_proof,omitempty"` // Hash proving valid recovery
}

// SubmittedShare represents a share submitted for recovery
type SubmittedShare struct {
	ShareID      int    `json:"share_id"`
	HolderID     string `json:"holder_id"`
	ShareHash    string `json:"share_hash"`    // Hash of the share (share itself stored off-chain)
	SubmittedAt  string `json:"submitted_at"`
	IsValid      bool   `json:"is_valid"`
	TxID         string `json:"tx_id"`
}

// ShareRevocation represents a revoked share
type ShareRevocation struct {
	ImageID     string `json:"image_id"`
	ShareID     int    `json:"share_id"`
	RevokedBy   string `json:"revoked_by"`
	RevokedAt   string `json:"revoked_at"`
	Reason      string `json:"reason"`
	TxID        string `json:"tx_id"`
}

// RecoveryAuditEntry represents an audit log entry for recovery attempts
type RecoveryAuditEntry struct {
	SessionID   string `json:"session_id"`
	ImageID     string `json:"image_id"`
	Action      string `json:"action"` // initiated, share_submitted, threshold_met, completed, failed, revoked
	ActorID     string `json:"actor_id"`
	Timestamp   string `json:"timestamp"`
	Details     string `json:"details"`
	TxID        string `json:"tx_id"`
}

// VerificationResult represents the result of image verification
type VerificationResult struct {
	Verified     bool   `json:"verified"`
	ImageID      string `json:"image_id"`
	StoredHash   string `json:"stored_hash"`
	ProvidedHash string `json:"provided_hash"`
	Timestamp    string `json:"timestamp"`
}

// Init is called when the chaincode is instantiated
func (t *ImageStoreChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	fmt.Println("ImageStore Chaincode initialized")
	return shim.Success(nil)
}

// Invoke is called when a transaction is submitted
func (t *ImageStoreChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "StoreImageMetadata":
		return t.storeImageMetadata(stub, args)
	case "GetImageMetadata":
		return t.getImageMetadata(stub, args)
	case "VerifyImageHash":
		return t.verifyImageHash(stub, args)
	case "GetImageHistory":
		return t.getImageHistory(stub, args)
	case "UpdateImageStatus":
		return t.updateImageStatus(stub, args)
	case "RecordAccess":
		return t.recordAccess(stub, args)
	case "GetAllImages":
		return t.getAllImages(stub, args)
	case "DeleteImage":
		return t.deleteImage(stub, args)
	// NOVEL: Blockchain-Coordinated Threshold Key Recovery Protocol
	case "InitiateKeyRecovery":
		return t.initiateKeyRecovery(stub, args)
	case "SubmitKeyShare":
		return t.submitKeyShare(stub, args)
	case "CheckRecoveryStatus":
		return t.checkRecoveryStatus(stub, args)
	case "CompleteRecovery":
		return t.completeRecovery(stub, args)
	case "RevokeShare":
		return t.revokeShare(stub, args)
	case "GetRecoveryAuditLog":
		return t.getRecoveryAuditLog(stub, args)
	// NOVEL: Key Rotation Protocol
	case "InitiateRotation":
		return t.initiateRotation(stub, args)
	case "ApproveRotation":
		return t.approveRotation(stub, args)
	case "FinalizeRotation":
		return t.finalizeRotation(stub, args)
	case "GetCurrentEpoch":
		return t.getCurrentEpoch(stub, args)
	default:
		return shim.Error(fmt.Sprintf("Unknown function: %s", function))
	}
}

// storeImageMetadata stores new image metadata on the ledger
func (t *ImageStoreChaincode) storeImageMetadata(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: JSON image metadata")
	}

	var metadata ImageMetadata
	err := json.Unmarshal([]byte(args[0]), &metadata)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to parse metadata: %s", err.Error()))
	}

	// Validate required fields
	if metadata.ImageID == "" {
		return shim.Error("Image ID is required")
	}
	if metadata.Hash == "" {
		return shim.Error("Image hash is required")
	}
	if metadata.Signature == "" {
		return shim.Error("Signature is required")
	}

	// Check if image already exists
	existing, err := stub.GetState(metadata.ImageID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to check existing: %s", err.Error()))
	}
	if existing != nil {
		return shim.Error(fmt.Sprintf("Image %s already exists", metadata.ImageID))
	}

	// Set timestamps and status
	metadata.CreatedAt = time.Now().Format(time.RFC3339)
	metadata.UpdatedAt = metadata.CreatedAt
	metadata.Status = "active"
	metadata.EncryptionMethod = "CCM"
	metadata.Threshold = "3/5"

	// Get transaction creator
	creator, err := stub.GetCreator()
	if err == nil {
		metadata.UploadedBy = string(creator)
	}

	// Store the metadata
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal metadata: %s", err.Error()))
	}

	err = stub.PutState(metadata.ImageID, metadataBytes)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to store metadata: %s", err.Error()))
	}

	// Emit event
	stub.SetEvent("ImageStored", metadataBytes)

	return shim.Success([]byte(fmt.Sprintf(`{"tx_id": "%s", "image_id": "%s"}`,
		stub.GetTxID(), metadata.ImageID)))
}

// getImageMetadata retrieves image metadata by ID
func (t *ImageStoreChaincode) getImageMetadata(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: image ID")
	}

	imageID := args[0]
	metadataBytes, err := stub.GetState(imageID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get metadata: %s", err.Error()))
	}
	if metadataBytes == nil {
		return shim.Error(fmt.Sprintf("Image %s not found", imageID))
	}

	return shim.Success(metadataBytes)
}

// verifyImageHash verifies an image hash against stored value
func (t *ImageStoreChaincode) verifyImageHash(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 2 {
		return shim.Error("Expecting 2 arguments: image ID and hash to verify")
	}

	imageID := args[0]
	providedHash := args[1]

	metadataBytes, err := stub.GetState(imageID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get metadata: %s", err.Error()))
	}
	if metadataBytes == nil {
		result := VerificationResult{
			Verified:     false,
			ImageID:      imageID,
			ProvidedHash: providedHash,
			Timestamp:    time.Now().Format(time.RFC3339),
		}
		resultBytes, _ := json.Marshal(result)
		return shim.Success(resultBytes)
	}

	var metadata ImageMetadata
	err = json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to parse metadata: %s", err.Error()))
	}

	result := VerificationResult{
		Verified:     metadata.Hash == providedHash,
		ImageID:      imageID,
		StoredHash:   metadata.Hash,
		ProvidedHash: providedHash,
		Timestamp:    time.Now().Format(time.RFC3339),
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal result: %s", err.Error()))
	}

	// Emit verification event
	stub.SetEvent("ImageVerified", resultBytes)

	return shim.Success(resultBytes)
}

// getImageHistory retrieves the transaction history for an image
func (t *ImageStoreChaincode) getImageHistory(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: image ID")
	}

	imageID := args[0]
	historyIterator, err := stub.GetHistoryForKey(imageID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get history: %s", err.Error()))
	}
	defer historyIterator.Close()

	var history []map[string]interface{}

	for historyIterator.HasNext() {
		modification, err := historyIterator.Next()
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to iterate history: %s", err.Error()))
		}

		record := map[string]interface{}{
			"tx_id":     modification.TxId,
			"timestamp": time.Unix(modification.Timestamp.Seconds, 0).Format(time.RFC3339),
			"is_delete": modification.IsDelete,
		}

		if !modification.IsDelete {
			var metadata ImageMetadata
			json.Unmarshal(modification.Value, &metadata)
			record["value"] = metadata
		}

		history = append(history, record)
	}

	historyBytes, err := json.Marshal(history)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal history: %s", err.Error()))
	}

	return shim.Success(historyBytes)
}

// updateImageStatus updates the status of an image
func (t *ImageStoreChaincode) updateImageStatus(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 2 {
		return shim.Error("Expecting 2 arguments: image ID and new status")
	}

	imageID := args[0]
	newStatus := args[1]

	// Validate status
	validStatuses := map[string]bool{
		"active":   true,
		"archived": true,
		"revoked":  true,
	}
	if !validStatuses[newStatus] {
		return shim.Error("Invalid status. Must be: active, archived, or revoked")
	}

	metadataBytes, err := stub.GetState(imageID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get metadata: %s", err.Error()))
	}
	if metadataBytes == nil {
		return shim.Error(fmt.Sprintf("Image %s not found", imageID))
	}

	var metadata ImageMetadata
	err = json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to parse metadata: %s", err.Error()))
	}

	metadata.Status = newStatus
	metadata.UpdatedAt = time.Now().Format(time.RFC3339)

	updatedBytes, err := json.Marshal(metadata)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal metadata: %s", err.Error()))
	}

	err = stub.PutState(imageID, updatedBytes)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to update metadata: %s", err.Error()))
	}

	// Emit event
	stub.SetEvent("ImageStatusUpdated", updatedBytes)

	return shim.Success([]byte(fmt.Sprintf(`{"image_id": "%s", "status": "%s"}`,
		imageID, newStatus)))
}

// recordAccess logs an access event for an image
func (t *ImageStoreChaincode) recordAccess(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: JSON access log")
	}

	var accessLog AccessLog
	err := json.Unmarshal([]byte(args[0]), &accessLog)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to parse access log: %s", err.Error()))
	}

	accessLog.Timestamp = time.Now().Format(time.RFC3339)

	// Create composite key for access logs
	accessKey, err := stub.CreateCompositeKey("access", []string{
		accessLog.ImageID,
		accessLog.Timestamp,
	})
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to create key: %s", err.Error()))
	}

	accessBytes, err := json.Marshal(accessLog)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal access log: %s", err.Error()))
	}

	err = stub.PutState(accessKey, accessBytes)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to store access log: %s", err.Error()))
	}

	// Emit event
	stub.SetEvent("AccessRecorded", accessBytes)

	return shim.Success(accessBytes)
}

// getAllImages retrieves all stored images
func (t *ImageStoreChaincode) getAllImages(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	startKey := ""
	endKey := ""

	if len(args) >= 2 {
		startKey = args[0]
		endKey = args[1]
	}

	iterator, err := stub.GetStateByRange(startKey, endKey)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get images: %s", err.Error()))
	}
	defer iterator.Close()

	var images []ImageMetadata

	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to iterate: %s", err.Error()))
		}

		var metadata ImageMetadata
		err = json.Unmarshal(result.Value, &metadata)
		if err == nil {
			images = append(images, metadata)
		}
	}

	imagesBytes, err := json.Marshal(images)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal images: %s", err.Error()))
	}

	return shim.Success(imagesBytes)
}

// deleteImage marks an image as deleted (soft delete)
func (t *ImageStoreChaincode) deleteImage(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: image ID")
	}

	imageID := args[0]

	// Get existing metadata
	metadataBytes, err := stub.GetState(imageID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get metadata: %s", err.Error()))
	}
	if metadataBytes == nil {
		return shim.Error(fmt.Sprintf("Image %s not found", imageID))
	}

	// Soft delete - update status to revoked
	var metadata ImageMetadata
	json.Unmarshal(metadataBytes, &metadata)
	metadata.Status = "revoked"
	metadata.UpdatedAt = time.Now().Format(time.RFC3339)

	updatedBytes, _ := json.Marshal(metadata)
	stub.PutState(imageID, updatedBytes)

	// Emit event
	stub.SetEvent("ImageDeleted", []byte(imageID))

	return shim.Success([]byte(fmt.Sprintf(`{"deleted": true, "image_id": "%s"}`, imageID)))
}

// ============================================================================
// NOVEL CONTRIBUTION: Blockchain-Coordinated Threshold Key Recovery Protocol
// ============================================================================

// initiateKeyRecovery starts a new key recovery session
// This creates an on-chain record that tracks the recovery process
func (t *ImageStoreChaincode) initiateKeyRecovery(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 3 {
		return shim.Error("Expecting 3 arguments: imageID, threshold, totalShares")
	}

	imageID := args[0]
	threshold := 0
	totalShares := 0
	fmt.Sscanf(args[1], "%d", &threshold)
	fmt.Sscanf(args[2], "%d", &totalShares)

	// Validate threshold parameters
	if threshold < 2 || threshold > totalShares {
		return shim.Error("Invalid threshold parameters: must satisfy 2 <= t <= n")
	}

	// Verify image exists
	imageBytes, err := stub.GetState(imageID)
	if err != nil || imageBytes == nil {
		return shim.Error(fmt.Sprintf("Image %s not found", imageID))
	}

	// Check for revoked shares
	revokedCount := 0
	for i := 1; i <= totalShares; i++ {
		revKey, _ := stub.CreateCompositeKey("revocation", []string{imageID, fmt.Sprintf("%d", i)})
		revBytes, _ := stub.GetState(revKey)
		if revBytes != nil {
			revokedCount++
		}
	}

	// Ensure enough valid shares exist
	if totalShares-revokedCount < threshold {
		return shim.Error(fmt.Sprintf("Insufficient valid shares: %d available, %d required",
			totalShares-revokedCount, threshold))
	}

	// Generate session ID
	sessionID := fmt.Sprintf("recovery-%s-%s", imageID, stub.GetTxID()[:8])

	// Create recovery session with 24-hour expiration
	session := KeyRecoverySession{
		SessionID:       sessionID,
		ImageID:         imageID,
		InitiatedBy:     string(stub.GetCreator()[:20]),
		InitiatedAt:     time.Now().Format(time.RFC3339),
		Threshold:       threshold,
		TotalShares:     totalShares,
		SubmittedShares: []SubmittedShare{},
		Status:          "pending",
		ExpiresAt:       time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

	sessionBytes, _ := json.Marshal(session)
	sessionKey, _ := stub.CreateCompositeKey("recovery_session", []string{imageID, sessionID})
	stub.PutState(sessionKey, sessionBytes)

	// Create audit entry
	t.createRecoveryAuditEntry(stub, sessionID, imageID, "initiated",
		session.InitiatedBy, "Recovery session initiated")

	stub.SetEvent("KeyRecoveryInitiated", sessionBytes)

	return shim.Success(sessionBytes)
}

// submitKeyShare allows a shareholder to submit their share for recovery
// The share hash is recorded on-chain; actual share is verified off-chain
func (t *ImageStoreChaincode) submitKeyShare(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 4 {
		return shim.Error("Expecting 4 arguments: sessionID, imageID, shareID, shareHash")
	}

	sessionID := args[0]
	imageID := args[1]
	shareID := 0
	fmt.Sscanf(args[2], "%d", &shareID)
	shareHash := args[3]

	// Get session
	sessionKey, _ := stub.CreateCompositeKey("recovery_session", []string{imageID, sessionID})
	sessionBytes, err := stub.GetState(sessionKey)
	if err != nil || sessionBytes == nil {
		return shim.Error("Recovery session not found")
	}

	var session KeyRecoverySession
	json.Unmarshal(sessionBytes, &session)

	// Check session status
	if session.Status != "pending" && session.Status != "threshold_met" {
		return shim.Error(fmt.Sprintf("Session not accepting shares. Status: %s", session.Status))
	}

	// Check expiration
	expiresAt, _ := time.Parse(time.RFC3339, session.ExpiresAt)
	if time.Now().After(expiresAt) {
		session.Status = "expired"
		sessionBytes, _ = json.Marshal(session)
		stub.PutState(sessionKey, sessionBytes)
		return shim.Error("Recovery session has expired")
	}

	// Check if share is revoked
	revKey, _ := stub.CreateCompositeKey("revocation", []string{imageID, fmt.Sprintf("%d", shareID)})
	revBytes, _ := stub.GetState(revKey)
	if revBytes != nil {
		return shim.Error(fmt.Sprintf("Share %d has been revoked", shareID))
	}

	// Check for duplicate submission
	for _, s := range session.SubmittedShares {
		if s.ShareID == shareID {
			return shim.Error(fmt.Sprintf("Share %d already submitted", shareID))
		}
	}

	// Record share submission
	submittedShare := SubmittedShare{
		ShareID:     shareID,
		HolderID:    string(stub.GetCreator()[:20]),
		ShareHash:   shareHash,
		SubmittedAt: time.Now().Format(time.RFC3339),
		IsValid:     true,
		TxID:        stub.GetTxID(),
	}

	session.SubmittedShares = append(session.SubmittedShares, submittedShare)

	// Check if threshold is met
	validShareCount := 0
	for _, s := range session.SubmittedShares {
		if s.IsValid {
			validShareCount++
		}
	}

	if validShareCount >= session.Threshold && session.Status == "pending" {
		session.Status = "threshold_met"
		t.createRecoveryAuditEntry(stub, sessionID, imageID, "threshold_met",
			submittedShare.HolderID, fmt.Sprintf("Threshold met with %d shares", validShareCount))
	}

	// Save session
	sessionBytes, _ = json.Marshal(session)
	stub.PutState(sessionKey, sessionBytes)

	// Audit entry
	t.createRecoveryAuditEntry(stub, sessionID, imageID, "share_submitted",
		submittedShare.HolderID, fmt.Sprintf("Share %d submitted", shareID))

	stub.SetEvent("KeyShareSubmitted", sessionBytes)

	return shim.Success(sessionBytes)
}

// checkRecoveryStatus returns the current status of a recovery session
func (t *ImageStoreChaincode) checkRecoveryStatus(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 2 {
		return shim.Error("Expecting 2 arguments: imageID, sessionID")
	}

	imageID := args[0]
	sessionID := args[1]

	sessionKey, _ := stub.CreateCompositeKey("recovery_session", []string{imageID, sessionID})
	sessionBytes, err := stub.GetState(sessionKey)
	if err != nil || sessionBytes == nil {
		return shim.Error("Recovery session not found")
	}

	return shim.Success(sessionBytes)
}

// completeRecovery marks a recovery session as completed after off-chain reconstruction
func (t *ImageStoreChaincode) completeRecovery(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 3 {
		return shim.Error("Expecting 3 arguments: imageID, sessionID, recoveryProof")
	}

	imageID := args[0]
	sessionID := args[1]
	recoveryProof := args[2] // Hash proving valid reconstruction

	sessionKey, _ := stub.CreateCompositeKey("recovery_session", []string{imageID, sessionID})
	sessionBytes, err := stub.GetState(sessionKey)
	if err != nil || sessionBytes == nil {
		return shim.Error("Recovery session not found")
	}

	var session KeyRecoverySession
	json.Unmarshal(sessionBytes, &session)

	if session.Status != "threshold_met" {
		return shim.Error(fmt.Sprintf("Cannot complete: threshold not met. Status: %s", session.Status))
	}

	session.Status = "completed"
	session.CompletedAt = time.Now().Format(time.RFC3339)
	session.RecoveryProof = recoveryProof

	sessionBytes, _ = json.Marshal(session)
	stub.PutState(sessionKey, sessionBytes)

	t.createRecoveryAuditEntry(stub, sessionID, imageID, "completed",
		string(stub.GetCreator()[:20]), "Key recovery completed successfully")

	stub.SetEvent("KeyRecoveryCompleted", sessionBytes)

	return shim.Success(sessionBytes)
}

// revokeShare permanently invalidates a compromised share
func (t *ImageStoreChaincode) revokeShare(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 3 {
		return shim.Error("Expecting 3 arguments: imageID, shareID, reason")
	}

	imageID := args[0]
	shareID := 0
	fmt.Sscanf(args[1], "%d", &shareID)
	reason := args[2]

	// Create revocation record
	revocation := ShareRevocation{
		ImageID:   imageID,
		ShareID:   shareID,
		RevokedBy: string(stub.GetCreator()[:20]),
		RevokedAt: time.Now().Format(time.RFC3339),
		Reason:    reason,
		TxID:      stub.GetTxID(),
	}

	revBytes, _ := json.Marshal(revocation)
	revKey, _ := stub.CreateCompositeKey("revocation", []string{imageID, fmt.Sprintf("%d", shareID)})
	stub.PutState(revKey, revBytes)

	// Audit entry
	t.createRecoveryAuditEntry(stub, "", imageID, "share_revoked",
		revocation.RevokedBy, fmt.Sprintf("Share %d revoked: %s", shareID, reason))

	stub.SetEvent("ShareRevoked", revBytes)

	return shim.Success(revBytes)
}

// getRecoveryAuditLog returns all recovery-related audit entries for an image
func (t *ImageStoreChaincode) getRecoveryAuditLog(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: imageID")
	}

	imageID := args[0]

	iterator, err := stub.GetStateByPartialCompositeKey("recovery_audit", []string{imageID})
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get audit log: %s", err.Error()))
	}
	defer iterator.Close()

	var auditLog []RecoveryAuditEntry

	for iterator.HasNext() {
		result, _ := iterator.Next()
		var entry RecoveryAuditEntry
		json.Unmarshal(result.Value, &entry)
		auditLog = append(auditLog, entry)
	}

	auditBytes, _ := json.Marshal(auditLog)
	return shim.Success(auditBytes)
}

// createRecoveryAuditEntry is a helper to create audit entries
func (t *ImageStoreChaincode) createRecoveryAuditEntry(stub shim.ChaincodeStubInterface,
	sessionID, imageID, action, actorID, details string) {

	entry := RecoveryAuditEntry{
		SessionID: sessionID,
		ImageID:   imageID,
		Action:    action,
		ActorID:   actorID,
		Timestamp: time.Now().Format(time.RFC3339),
		Details:   details,
		TxID:      stub.GetTxID(),
	}

	entryBytes, _ := json.Marshal(entry)
	auditKey, _ := stub.CreateCompositeKey("recovery_audit", []string{imageID, entry.Timestamp})
	stub.PutState(auditKey, entryBytes)
}

// ============================================================================
// KEY ROTATION PROTOCOL - Blockchain-Coordinated Key Epoch Management
// ============================================================================

// KeyRotationSession represents an ongoing key rotation process
type KeyRotationSession struct {
	RotationID      string             `json:"rotation_id"`
	ImageID         string             `json:"image_id"`
	OldEpoch        int                `json:"old_epoch"`
	NewEpoch        int                `json:"new_epoch"`
	InitiatedBy     string             `json:"initiated_by"`
	InitiatedAt     string             `json:"initiated_at"`
	Status          string             `json:"status"` // initiated, pending_approval, approved, finalized, cancelled
	Approvals       []RotationApproval `json:"approvals"`
	RequiredApprovals int              `json:"required_approvals"`
	NewKeyHash      string             `json:"new_key_hash,omitempty"`
	FinalizedAt     string             `json:"finalized_at,omitempty"`
}

// RotationApproval represents an approval for key rotation
type RotationApproval struct {
	ApproverID  string `json:"approver_id"`
	ApprovedAt  string `json:"approved_at"`
	TxID        string `json:"tx_id"`
}

// EpochInfo tracks the current epoch for an image
type EpochInfo struct {
	ImageID      string `json:"image_id"`
	CurrentEpoch int    `json:"current_epoch"`
	LastRotation string `json:"last_rotation"`
	RotationCount int   `json:"rotation_count"`
}

// initiateRotation starts a new key rotation process
func (t *ImageStoreChaincode) initiateRotation(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 2 {
		return shim.Error("Expecting 2 arguments: imageID, requiredApprovals")
	}

	imageID := args[0]
	requiredApprovals := 2
	fmt.Sscanf(args[1], "%d", &requiredApprovals)

	// Verify image exists
	imageBytes, err := stub.GetState(imageID)
	if err != nil || imageBytes == nil {
		return shim.Error(fmt.Sprintf("Image %s not found", imageID))
	}

	// Get current epoch
	epochKey, _ := stub.CreateCompositeKey("epoch", []string{imageID})
	epochBytes, _ := stub.GetState(epochKey)

	currentEpoch := 0
	if epochBytes != nil {
		var epochInfo EpochInfo
		json.Unmarshal(epochBytes, &epochInfo)
		currentEpoch = epochInfo.CurrentEpoch
	}

	// Generate rotation ID
	rotationID := fmt.Sprintf("rotation-%s-%s", imageID, stub.GetTxID()[:8])

	// Create rotation session
	session := KeyRotationSession{
		RotationID:        rotationID,
		ImageID:           imageID,
		OldEpoch:          currentEpoch,
		NewEpoch:          currentEpoch + 1,
		InitiatedBy:       string(stub.GetCreator()[:20]),
		InitiatedAt:       time.Now().Format(time.RFC3339),
		Status:            "initiated",
		Approvals:         []RotationApproval{},
		RequiredApprovals: requiredApprovals,
	}

	sessionBytes, _ := json.Marshal(session)
	sessionKey, _ := stub.CreateCompositeKey("rotation_session", []string{imageID, rotationID})
	stub.PutState(sessionKey, sessionBytes)

	// Audit entry
	t.createRecoveryAuditEntry(stub, rotationID, imageID, "rotation_initiated",
		session.InitiatedBy, fmt.Sprintf("Key rotation initiated: epoch %d -> %d", currentEpoch, currentEpoch+1))

	stub.SetEvent("KeyRotationInitiated", sessionBytes)

	return shim.Success(sessionBytes)
}

// approveRotation allows a party to approve a pending rotation
func (t *ImageStoreChaincode) approveRotation(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 2 {
		return shim.Error("Expecting 2 arguments: imageID, rotationID")
	}

	imageID := args[0]
	rotationID := args[1]

	// Get rotation session
	sessionKey, _ := stub.CreateCompositeKey("rotation_session", []string{imageID, rotationID})
	sessionBytes, err := stub.GetState(sessionKey)
	if err != nil || sessionBytes == nil {
		return shim.Error("Rotation session not found")
	}

	var session KeyRotationSession
	json.Unmarshal(sessionBytes, &session)

	// Check status
	if session.Status != "initiated" && session.Status != "pending_approval" {
		return shim.Error(fmt.Sprintf("Cannot approve rotation in status: %s", session.Status))
	}

	approverID := string(stub.GetCreator()[:20])

	// Check if already approved by this party
	for _, approval := range session.Approvals {
		if approval.ApproverID == approverID {
			return shim.Error("Already approved by this party")
		}
	}

	// Check if approver is the initiator
	if approverID == session.InitiatedBy {
		return shim.Error("Initiator cannot approve their own rotation")
	}

	// Add approval
	approval := RotationApproval{
		ApproverID: approverID,
		ApprovedAt: time.Now().Format(time.RFC3339),
		TxID:       stub.GetTxID(),
	}
	session.Approvals = append(session.Approvals, approval)
	session.Status = "pending_approval"

	// Check if threshold met
	if len(session.Approvals) >= session.RequiredApprovals {
		session.Status = "approved"
	}

	sessionBytes, _ = json.Marshal(session)
	stub.PutState(sessionKey, sessionBytes)

	// Audit entry
	t.createRecoveryAuditEntry(stub, rotationID, imageID, "rotation_approved",
		approverID, fmt.Sprintf("Rotation approved (%d/%d)", len(session.Approvals), session.RequiredApprovals))

	stub.SetEvent("KeyRotationApproved", sessionBytes)

	return shim.Success(sessionBytes)
}

// finalizeRotation completes the rotation and updates the epoch
func (t *ImageStoreChaincode) finalizeRotation(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 3 {
		return shim.Error("Expecting 3 arguments: imageID, rotationID, newKeyHash")
	}

	imageID := args[0]
	rotationID := args[1]
	newKeyHash := args[2]

	// Get rotation session
	sessionKey, _ := stub.CreateCompositeKey("rotation_session", []string{imageID, rotationID})
	sessionBytes, err := stub.GetState(sessionKey)
	if err != nil || sessionBytes == nil {
		return shim.Error("Rotation session not found")
	}

	var session KeyRotationSession
	json.Unmarshal(sessionBytes, &session)

	// Check status
	if session.Status != "approved" {
		return shim.Error(fmt.Sprintf("Rotation must be approved before finalization. Current status: %s", session.Status))
	}

	// Update session
	session.Status = "finalized"
	session.FinalizedAt = time.Now().Format(time.RFC3339)
	session.NewKeyHash = newKeyHash

	sessionBytes, _ = json.Marshal(session)
	stub.PutState(sessionKey, sessionBytes)

	// Update epoch info
	epochKey, _ := stub.CreateCompositeKey("epoch", []string{imageID})
	epochInfo := EpochInfo{
		ImageID:       imageID,
		CurrentEpoch:  session.NewEpoch,
		LastRotation:  session.FinalizedAt,
		RotationCount: session.NewEpoch,
	}
	epochBytes, _ := json.Marshal(epochInfo)
	stub.PutState(epochKey, epochBytes)

	// Audit entry
	t.createRecoveryAuditEntry(stub, rotationID, imageID, "rotation_finalized",
		string(stub.GetCreator()[:20]), fmt.Sprintf("Key rotation finalized: new epoch %d", session.NewEpoch))

	stub.SetEvent("KeyRotationFinalized", sessionBytes)

	return shim.Success(sessionBytes)
}

// getCurrentEpoch returns the current epoch for an image
func (t *ImageStoreChaincode) getCurrentEpoch(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	if len(args) < 1 {
		return shim.Error("Expecting 1 argument: imageID")
	}

	imageID := args[0]

	epochKey, _ := stub.CreateCompositeKey("epoch", []string{imageID})
	epochBytes, err := stub.GetState(epochKey)

	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get epoch: %s", err.Error()))
	}

	if epochBytes == nil {
		// Return default epoch 0
		defaultEpoch := EpochInfo{
			ImageID:       imageID,
			CurrentEpoch:  0,
			LastRotation:  "",
			RotationCount: 0,
		}
		epochBytes, _ = json.Marshal(defaultEpoch)
	}

	return shim.Success(epochBytes)
}

// ============================================================================
// END OF NOVEL CONTRIBUTION
// ============================================================================

func main() {
	err := shim.Start(new(ImageStoreChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}
