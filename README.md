# Blockchain-Based Secure Medical Image Storage System

## Supplementary Materials for PeerJ Computer Science Submission

This repository contains the implementation code and configuration files for the secure medical image storage system described in the paper "Integration of Chaos-Based Encryption and Blockchain for Tamper-Proof Medical Image Storage and Authentication".

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MEDICAL IMAGE SECURITY SYSTEM                        │
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

## Directory Structure

```
supplementary-files/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── src/
│   ├── encryption/
│   │   ├── __init__.py
│   │   ├── ccm_encryption.py   # Chaotic Cat Map encryption
│   │   └── ccm_color.py        # Color image encryption
│   ├── secret_sharing/
│   │   ├── __init__.py
│   │   └── shamir.py           # Shamir's Secret Sharing (3,5)
│   ├── signature/
│   │   ├── __init__.py
│   │   └── rsa_signature.py    # RSA digital signatures
│   └── blockchain/
│       ├── __init__.py
│       └── fabric_client.py    # Hyperledger Fabric client
├── chaincode/
│   ├── go.mod
│   ├── go.sum
│   └── imagestore.go           # Smart contract (Go)
├── network/
│   ├── configtx.yaml           # Channel configuration
│   ├── crypto-config.yaml      # Cryptographic material config
│   └── docker-compose.yaml     # Network deployment
├── docker/
│   ├── Dockerfile.peer
│   ├── Dockerfile.orderer
│   └── Dockerfile.ca
├── tests/
│   ├── test_encryption.py
│   ├── test_secret_sharing.py
│   └── test_signature.py
└── examples/
    ├── encrypt_image.py
    ├── store_to_blockchain.py
    └── verify_image.py
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
    channel_name="medical-images",
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
configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID medical-images
```

### 3. Start the Network

```bash
docker-compose -f docker-compose.yaml up -d
```

### 4. Deploy Chaincode

```bash
peer lifecycle chaincode package imagestore.tar.gz --path ./chaincode --lang golang --label imagestore_1.0
peer lifecycle chaincode install imagestore.tar.gz
peer lifecycle chaincode approveformyorg --channelID medical-images --name imagestore --version 1.0 --package-id $PACKAGE_ID --sequence 1
peer lifecycle chaincode commit --channelID medical-images --name imagestore --version 1.0 --sequence 1
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

This code is provided for academic and research purposes as supplementary material for the PeerJ Computer Science submission.

## Citation

If you use this code, please cite:

```bibtex
@article{tuncer2026blockchain,
  title={Integration of Chaos-Based Encryption and Blockchain for Tamper-Proof Medical Image Storage and Authentication},
  author={Tuncer, Sefa and ...},
  journal={PeerJ Computer Science},
  year={2026}
}
```

## Contact

For questions regarding the implementation, please contact the corresponding author.
