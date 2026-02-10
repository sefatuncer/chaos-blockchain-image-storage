# Chaos-Based Encryption with Blockchain Verification

A secure image storage and verification system integrating chaotic encryption, threshold secret sharing, and blockchain-based verification.

## Overview

This repository provides a complete implementation for secure image storage and verification featuring:
- **Chaotic Cat Map (CCM) Encryption** - Chaos-based image encryption with 256-bit key space
- **Shamir's Secret Sharing** - (t,n) threshold key distribution
- **RSA Digital Signatures** - Image authentication and integrity verification
- **Hyperledger Fabric Integration** - Immutable audit trail and decentralized verification
- **Blockchain-Coordinated Key Recovery** - Novel on-chain threshold enforcement protocol

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURE IMAGE VERIFICATION SYSTEM                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────┐  │
│   │   Original   │───▶│     CCM      │───▶│    Encrypted Image          │  │
│   │    Image     │    │  Encryption  │    │                              │  │
│   └──────────────┘    └──────────────┘    └──────────────────────────────┘  │
│                              │                          │                    │
│                              ▼                          ▼                    │
│                    ┌──────────────┐           ┌──────────────────┐          │
│                    │  Encryption  │           │    SHA-256       │          │
│                    │     Key      │           │     Hash         │          │
│                    └──────────────┘           └──────────────────┘          │
│                              │                          │                    │
│                              ▼                          ▼                    │
│                    ┌──────────────┐           ┌──────────────────┐          │
│                    │   Shamir's   │           │  RSA Signature   │          │
│                    │   (3,5) SSS  │           │                  │          │
│                    └──────────────┘           └──────────────────┘          │
│                              │                          │                    │
│                              ▼                          ▼                    │
│              ┌───────────────────────────────────────────────┐              │
│              │          HYPERLEDGER FABRIC BLOCKCHAIN         │              │
│              │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐│              │
│              │  │  Peer   │  │ Orderer │  │  Smart Contract ││              │
│              │  │  Nodes  │  │ Service │  │   (Chaincode)   ││              │
│              │  └─────────┘  └─────────┘  └─────────────────┘│              │
│              └───────────────────────────────────────────────┘              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Software Requirements

- Python 3.8+
- Go 1.19+
- Docker 20.10+
- Docker Compose 2.0+
- Node.js 16+ (for Fabric SDK)

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Hyperledger Fabric

```bash
# Download Fabric binaries and Docker images
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

## Quick Start

### 1. Image Encryption

```python
from src.encryption.ccm_encryption import ChaoticCatMapEncryption

# Initialize encryptor
ccm = ChaoticCatMapEncryption()

# Encrypt image
encrypted, key = ccm.encrypt("path/to/image.png")

# Save encrypted image
ccm.save_encrypted(encrypted, "encrypted_image.png")
```

### 2. Secret Sharing

```python
from src.secret_sharing.shamir import ShamirSecretSharing

# Initialize with (3,5) threshold
sss = ShamirSecretSharing(threshold=3, num_shares=5)

# Split the encryption key
shares = sss.split_secret(key)

# Reconstruct with any 3 shares
recovered_key = sss.reconstruct_secret(shares[:3])
```

### 3. Digital Signature

```python
from src.signature.rsa_signature import RSASignature

# Initialize
signer = RSASignature()

# Sign the image hash
signature = signer.sign(image_hash)

# Verify signature
is_valid = signer.verify(image_hash, signature)
```

### 4. Blockchain Storage

```python
from src.blockchain.fabric_client import FabricClient

# Connect to Hyperledger Fabric network
client = FabricClient(
    channel_name="secure-images",
    chaincode_name="imagestore"
)

# Store image metadata
tx_id = client.store_image_metadata(
    image_id="IMG001",
    hash_value=image_hash,
    signature=signature,
    encrypted_shares=shares
)
```

## Network Setup

### 1. Generate Cryptographic Materials

```bash
cd network
cryptogen generate --config=./crypto-config.yaml
```

### 2. Create Channel Artifacts

```bash
configtxgen -profile TwoOrgsOrdererGenesis -channelID system-channel -outputBlock ./channel-artifacts/genesis.block
configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID secure-images
```

### 3. Start the Network

```bash
docker-compose -f docker-compose.yaml up -d
```

### 4. Deploy Chaincode

```bash
peer lifecycle chaincode package imagestore.tar.gz --path ./chaincode --lang golang --label imagestore_1.0
peer lifecycle chaincode install imagestore.tar.gz
peer lifecycle chaincode approveformyorg --channelID secure-images --name imagestore --version 1.0 --package-id $PACKAGE_ID --sequence 1
peer lifecycle chaincode commit --channelID secure-images --name imagestore --version 1.0 --sequence 1
```

## Security Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| CCM Iterations | 10 | Number of Cat Map iterations |
| RSA Key Size | 2048 bits | Digital signature key size |
| SHA Hash | SHA-256 | Hashing algorithm |
| SSS Threshold | (3,5) | 3 of 5 shares required |
| Fabric Endorsement | 2 of 3 | Required endorsements |

## Performance Metrics

Based on experimental results:

| Metric | Grayscale | Color (RGB) |
|--------|-----------|-------------|
| Entropy | 7.9974 | 7.9993 |
| NPCR | 99.61% | 99.60% |
| UACI | 33.46% | 33.41% |
| Horizontal Correlation | 0.0012 | 0.0089 |
| Vertical Correlation | 0.0008 | 0.0124 |
| Diagonal Correlation | 0.0015 | 0.0098 |

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test
pytest tests/test_encryption.py -v
```

## License

This code is provided under MIT License for academic and research purposes.

## Contact

For questions regarding the implementation, please contact the corresponding author.
