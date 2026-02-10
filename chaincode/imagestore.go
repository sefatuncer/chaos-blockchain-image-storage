/*
Medical Image Storage Chaincode for Hyperledger Fabric

This chaincode implements the smart contract for secure medical image
metadata storage and verification on Hyperledger Fabric blockchain.

Reference:
"Integration of Chaos-Based Encryption and Blockchain for Tamper-Proof
Medical Image Storage and Authentication"

Functions:
- StoreImageMetadata: Store encrypted image metadata
- GetImageMetadata: Retrieve image metadata by ID
- VerifyImageHash: Verify image integrity
- GetImageHistory: Get transaction history
- UpdateImageStatus: Update image status (active/archived/revoked)
- RecordAccess: Log access events
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

func main() {
	err := shim.Start(new(ImageStoreChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}
