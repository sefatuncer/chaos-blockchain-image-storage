# Chaotic Image Encryption and Verification with Blockchain Coordinated Threshold Secret Sharing

A secure image storage and verification system integrating chaotic encryption, threshold secret sharing, digital signatures and Hyperledger Fabric blockchain verification.

**Associated Paper:** Tuncer, S. & Karakuzu, C. (2025). *Chaotic Image Encryption and Verification with Blockchain Coordinated Threshold Secret Sharing.* PeerJ Computer Science (under review).

## Overview

This repository provides a complete implementation for secure image storage and verification featuring:
- **Chaotic Cat Map (CCM) Encryption** - Chaos-based image encryption with 256-bit key space
- **Cross-Channel Chaotic Coupling (C4) Protocol** - Inter-channel dependency for color image encryption
- **Shamir's Secret Sharing** - (t,n) threshold key distribution
- **Adaptive Threshold Algorithm (ATA)** - Dynamic risk-based threshold adjustment
- **RSA-2048 Digital Signatures** - Image authentication and integrity verification
- **Hyperledger Fabric Integration** - Immutable audit trail and decentralized verification
- **On-Chain Key Evolution** - Blockchain-coordinated key rotation without share redistribution

## System Architecture Overview

```
+-----------------------------------------------------------------------------+
|                     SECURE IMAGE VERIFICATION SYSTEM                         |
+-----------------------------------------------------------------------------+
|                                                                              |
|   Original Image --> CCM Encryption --> Encrypted Image --> SHA-256 Hash     |
|                           |                                     |            |
|                           v                                     v            |
|                    Encryption Key                         RSA Signature      |
|                           |                                     |            |
|                           v                                     v            |
|                    Shamir's (3,5) SSS            Hyperledger Fabric          |
|                                                  Blockchain Storage          |
|                                                                              |
+-----------------------------------------------------------------------------+
```

## Dataset Information

The experimental evaluation uses an extended test dataset (n=60 images across 7 categories):

| Category | Source | Count | Resolution | License |
|----------|--------|-------|------------|---------|
| Standard Benchmarks | [USC-SIPI Image Database](https://sipi.usc.edu/database/) | 10 | 256x256 - 512x512 | Public domain |
| Medical Grayscale | [NIH ChestX-ray14](https://nihcc.app.box.com/v/ChestXray-NIHCC) | 10 | 512x512 - 2048x2048 | CC0 1.0 |
| Satellite Imagery | [Copernicus Sentinel-2](https://dataspace.copernicus.eu/) | 5 | 1024x1024 - 4096x4096 | Copernicus Open Access |
| Color Standard | [USC-SIPI Image Database](https://sipi.usc.edu/database/) | 15 | 512x512 | Public domain |
| Medical Color | [ISIC Archive](https://www.isic-archive.com/) | 10 | 1024x1024 | CC-BY-NC |
| Document Color | Synthetically generated | 5 | 1024x768 | N/A |
| Synthetic Patterns | Programmatically generated | 5 | 512x512 | N/A |

Standard test images include: Airplane, Cameraman, Baboon, Peppers, Mandrill, Boat, Goldhill.

## Code Information

| Component | Language | Directory | Description |
|-----------|----------|-----------|-------------|
| CCM Encryption | Python | `src/encryption/` | Chaotic Cat Map encryption with 256-bit key space |
| C4 Protocol | Python | `src/encryption/c4_protocol.py` | Cross-channel chaotic coupling for color images |
| Key Rotation | Python | `src/encryption/key_rotation.py` | On-chain key evolution mechanism |
| Secret Sharing | Python | `src/secret_sharing/` | Shamir's SSS and Adaptive Threshold Algorithm |
| Digital Signature | Python | `src/signature/` | RSA-2048 signing and verification |
| Fabric Client | Python | `src/blockchain/` | Hyperledger Fabric SDK integration |
| Smart Contract | Go | `chaincode/` | Chaincode for image metadata storage |
| Network Config | YAML/Docker | `network/`, `docker/` | Fabric network configuration |
| Tests | Python | `tests/` | Unit tests and benchmarks |

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

## Usage Instructions

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

### 5. Network Setup

```bash
# Generate cryptographic materials
cd network
cryptogen generate --config=./crypto-config.yaml

# Create channel artifacts
configtxgen -profile TwoOrgsOrdererGenesis -channelID system-channel -outputBlock ./channel-artifacts/genesis.block
configtxgen -profile TwoOrgsChannel -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID secure-images

# Start the network
docker-compose -f docker-compose.yaml up -d

# Deploy chaincode
peer lifecycle chaincode package imagestore.tar.gz --path ./chaincode --lang golang --label imagestore_1.0
peer lifecycle chaincode install imagestore.tar.gz
peer lifecycle chaincode approveformyorg --channelID secure-images --name imagestore --version 1.0 --package-id $PACKAGE_ID --sequence 1
peer lifecycle chaincode commit --channelID secure-images --name imagestore --version 1.0 --sequence 1
```

## Methodology

The system follows a multi-layered security approach:

1. **Image Encryption**: The Chaotic Cat Map (CCM) algorithm encrypts images using 256-bit keys. For color images, the Cross-Channel Chaotic Coupling (C4) Protocol ensures inter-channel dependency, achieving 75% reduction in inter-channel correlation.

2. **Key Distribution**: Shamir's Secret Sharing splits the encryption key into n shares with a (t,n) threshold. The Adaptive Threshold Algorithm dynamically adjusts the threshold based on real-time risk assessment.

3. **Digital Signatures**: RSA-2048 signatures provide non-repudiation. Each shareholder signs the SHA-256 hash of the encrypted image.

4. **Blockchain Verification**: Hyperledger Fabric stores encrypted image hashes, shareholder signatures and timestamps as immutable records. The Raft consensus mechanism ensures consistency across 2 organizations with 8 peer nodes.

5. **Key Rotation**: On-Chain Key Evolution enables key rotation without share redistribution, providing forward and backward secrecy.

## Security Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| CCM Key Space | 256 bits | Encryption key size |
| CCM Iterations | 10 | Number of Cat Map iterations |
| RSA Key Size | 2048 bits | Digital signature key size |
| SHA Hash | SHA-256 | Hashing algorithm |
| SSS Threshold | (3,5) | 3 of 5 shares required |
| Fabric Endorsement | 2 of 3 | Required endorsements |
| Fabric Version | 2.5.4 | Hyperledger Fabric version |
| Consensus | Raft (CFT) | Ordering service consensus |

## Performance Metrics

Based on experimental results (n=60 images):

| Metric | Grayscale (n=45) | Color/C4 (n=15) |
|--------|-------------------|-----------------|
| Entropy | 7.9974 | 7.9993 |
| NPCR | 99.60% | 99.61% |
| UACI | 33.48% | 33.49% |
| Correlation (H) | < 0.003 | < 0.009 |
| Correlation (V) | < 0.003 | < 0.007 |
| Blockchain Write (P50) | 1850 ms | 1850 ms |
| Blockchain Read (P50) | 156 ms | 156 ms |

## Testing

```bash
# Run all tests
pytest tests/

# Run specific tests
pytest tests/test_encryption.py -v
pytest tests/test_c4_protocol.py -v
pytest tests/test_adaptive_threshold.py -v
pytest tests/test_key_rotation.py -v
pytest tests/test_secret_sharing.py -v
pytest tests/test_signature.py -v

# Run benchmarks
python tests/benchmark.py
```

## Citation

If you use this code in your research, please cite:

```bibtex
@article{tuncer2025chaotic,
  author = {Tuncer, Sefa and Karakuzu, Cihan},
  title = {Chaotic Image Encryption and Verification with Blockchain Coordinated Threshold Secret Sharing},
  journal = {PeerJ Computer Science},
  year = {2025},
  note = {Under review}
}
```

## License

This code is provided under the [MIT License](LICENSE) for academic and research purposes.

## Contact

For questions regarding the implementation, please contact the corresponding author:
- **Sefa Tuncer** - tuncersefa@gmail.com
