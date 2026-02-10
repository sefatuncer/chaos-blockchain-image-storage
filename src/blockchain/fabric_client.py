"""
Hyperledger Fabric Client for Medical Image Storage

Provides a Python interface for interacting with the Hyperledger Fabric
blockchain network for storing and retrieving medical image metadata.

Reference:
"Integration of Chaos-Based Encryption and Blockchain for Tamper-Proof
Medical Image Storage and Authentication"
"""

import json
import hashlib
from typing import Dict, List, Optional
from datetime import datetime


class FabricClient:
    """
    Client for interacting with Hyperledger Fabric network.

    Handles connection to the blockchain network and invokes
    chaincode functions for image metadata operations.

    Attributes:
        channel_name: Name of the Fabric channel
        chaincode_name: Name of the deployed chaincode
        connection_profile: Path to connection profile
    """

    def __init__(self, channel_name: str = "medical-images",
                 chaincode_name: str = "imagestore",
                 connection_profile: str = None,
                 wallet_path: str = None,
                 identity: str = None):
        """
        Initialize the Fabric client.

        Args:
            channel_name: Name of the channel
            chaincode_name: Name of the chaincode
            connection_profile: Path to connection profile JSON
            wallet_path: Path to wallet directory
            identity: Identity to use for transactions
        """
        self.channel_name = channel_name
        self.chaincode_name = chaincode_name
        self.connection_profile = connection_profile
        self.wallet_path = wallet_path
        self.identity = identity

        # Connection state
        self._connected = False
        self._gateway = None
        self._network = None
        self._contract = None

        # Transaction history (for demo/testing)
        self._local_ledger = {}

    def connect(self) -> bool:
        """
        Establish connection to the Fabric network.

        Returns:
            True if connection successful
        """
        try:
            # In production, this would use the Fabric SDK
            # from hfc.fabric import Client
            # self._gateway = Client(net_profile=self.connection_profile)
            # self._network = self._gateway.get_channel(self.channel_name)
            # self._contract = self._network.chaincode(self.chaincode_name)

            # For demonstration purposes
            print(f"Connecting to channel: {self.channel_name}")
            print(f"Using chaincode: {self.chaincode_name}")
            self._connected = True
            return True

        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """Disconnect from the Fabric network."""
        self._connected = False
        self._gateway = None
        self._network = None
        self._contract = None

    def _generate_tx_id(self) -> str:
        """Generate a unique transaction ID."""
        timestamp = datetime.now().isoformat()
        data = f"{timestamp}-{len(self._local_ledger)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def store_image_metadata(self, image_id: str, hash_value: str,
                            signature: str, encrypted_shares: List[Dict],
                            metadata: Dict = None) -> str:
        """
        Store image metadata on the blockchain.

        Args:
            image_id: Unique identifier for the image
            hash_value: SHA-256 hash of the encrypted image
            signature: RSA signature of the hash
            encrypted_shares: List of key share information
            metadata: Additional metadata (patient ID, timestamp, etc.)

        Returns:
            Transaction ID
        """
        tx_id = self._generate_tx_id()

        # Prepare the record
        record = {
            'image_id': image_id,
            'hash': hash_value,
            'signature': signature,
            'shares': [
                {
                    'share_id': share['share_id'],
                    'share_hash': share.get('share_hash', '')
                }
                for share in encrypted_shares
            ],
            'metadata': metadata or {},
            'created_at': datetime.now().isoformat(),
            'tx_id': tx_id
        }

        # In production: submit transaction to blockchain
        # result = self._contract.submit_transaction(
        #     'StoreImageMetadata',
        #     json.dumps(record)
        # )

        # For demonstration: store locally
        self._local_ledger[image_id] = record
        print(f"Stored image metadata: {image_id} -> TX: {tx_id}")

        return tx_id

    def get_image_metadata(self, image_id: str) -> Optional[Dict]:
        """
        Retrieve image metadata from the blockchain.

        Args:
            image_id: The image identifier

        Returns:
            Image metadata dictionary or None
        """
        # In production: query blockchain
        # result = self._contract.evaluate_transaction(
        #     'GetImageMetadata',
        #     image_id
        # )

        return self._local_ledger.get(image_id)

    def verify_image(self, image_id: str, provided_hash: str) -> Dict:
        """
        Verify an image against stored blockchain metadata.

        Args:
            image_id: The image identifier
            provided_hash: Hash of the image to verify

        Returns:
            Verification result dictionary
        """
        stored = self.get_image_metadata(image_id)

        if not stored:
            return {
                'verified': False,
                'error': 'Image not found in blockchain'
            }

        hash_matches = stored['hash'] == provided_hash

        return {
            'verified': hash_matches,
            'image_id': image_id,
            'stored_hash': stored['hash'],
            'provided_hash': provided_hash,
            'original_tx_id': stored['tx_id'],
            'created_at': stored['created_at']
        }

    def get_image_history(self, image_id: str) -> List[Dict]:
        """
        Get the transaction history for an image.

        Args:
            image_id: The image identifier

        Returns:
            List of historical transactions
        """
        # In production: query blockchain history
        # result = self._contract.evaluate_transaction(
        #     'GetImageHistory',
        #     image_id
        # )

        stored = self.get_image_metadata(image_id)
        if stored:
            return [stored]  # Simplified for demo
        return []

    def list_images(self, start_key: str = "", end_key: str = "") -> List[Dict]:
        """
        List all stored images (with optional range).

        Args:
            start_key: Starting key for range query
            end_key: Ending key for range query

        Returns:
            List of image metadata records
        """
        # In production: range query on blockchain
        return list(self._local_ledger.values())

    def record_access(self, image_id: str, accessor_id: str,
                     access_type: str = "view") -> str:
        """
        Record an access event on the blockchain.

        Args:
            image_id: The accessed image
            accessor_id: ID of the accessor
            access_type: Type of access (view, download, modify)

        Returns:
            Access log transaction ID
        """
        tx_id = self._generate_tx_id()

        access_record = {
            'image_id': image_id,
            'accessor_id': accessor_id,
            'access_type': access_type,
            'timestamp': datetime.now().isoformat(),
            'tx_id': tx_id
        }

        print(f"Access recorded: {accessor_id} -> {image_id} ({access_type})")

        return tx_id

    def update_image_status(self, image_id: str, status: str,
                           reason: str = "") -> str:
        """
        Update the status of an image record.

        Args:
            image_id: The image identifier
            status: New status (active, archived, revoked)
            reason: Reason for status change

        Returns:
            Update transaction ID
        """
        tx_id = self._generate_tx_id()

        if image_id in self._local_ledger:
            self._local_ledger[image_id]['status'] = status
            self._local_ledger[image_id]['status_reason'] = reason
            self._local_ledger[image_id]['status_updated'] = datetime.now().isoformat()

        return tx_id


class MedicalImageBlockchain:
    """
    High-level interface for the medical image blockchain system.

    Combines all components (encryption, secret sharing, signatures,
    blockchain) into a unified workflow.
    """

    def __init__(self, channel_name: str = "medical-images"):
        """
        Initialize the medical image blockchain system.

        Args:
            channel_name: Fabric channel name
        """
        self.fabric_client = FabricClient(channel_name=channel_name)
        self.fabric_client.connect()

    def store_encrypted_image(self, image_id: str, encrypted_path: str,
                             encryption_key: Dict, shares: List[Dict],
                             signature: str, patient_id: str = None) -> str:
        """
        Complete workflow for storing an encrypted medical image.

        Args:
            image_id: Unique image identifier
            encrypted_path: Path to encrypted image file
            encryption_key: Encryption key dictionary
            shares: List of key shares
            signature: RSA signature
            patient_id: Optional patient identifier

        Returns:
            Blockchain transaction ID
        """
        # Hash the encrypted image
        import hashlib
        with open(encrypted_path, 'rb') as f:
            image_hash = hashlib.sha256(f.read()).hexdigest()

        # Prepare metadata
        metadata = {
            'patient_id': patient_id,
            'encryption_algorithm': 'CCM',
            'iterations': encryption_key.get('iterations', 10),
            'threshold': '3/5',
            'image_hash': image_hash
        }

        # Store on blockchain
        tx_id = self.fabric_client.store_image_metadata(
            image_id=image_id,
            hash_value=image_hash,
            signature=signature,
            encrypted_shares=shares,
            metadata=metadata
        )

        return tx_id

    def verify_and_retrieve(self, image_id: str,
                           current_hash: str) -> Dict:
        """
        Verify image integrity using blockchain.

        Args:
            image_id: Image to verify
            current_hash: Current hash of the image

        Returns:
            Verification result
        """
        return self.fabric_client.verify_image(image_id, current_hash)


if __name__ == "__main__":
    # Example usage
    print("Hyperledger Fabric Client Demo")
    print("=" * 50)

    # Initialize client
    client = FabricClient(
        channel_name="medical-images",
        chaincode_name="imagestore"
    )

    # Connect
    client.connect()

    # Store image metadata
    tx_id = client.store_image_metadata(
        image_id="IMG-2026-001",
        hash_value="abc123def456789...",
        signature="base64_signature_here...",
        encrypted_shares=[
            {'share_id': 1, 'share_hash': 'hash1'},
            {'share_id': 2, 'share_hash': 'hash2'},
            {'share_id': 3, 'share_hash': 'hash3'},
            {'share_id': 4, 'share_hash': 'hash4'},
            {'share_id': 5, 'share_hash': 'hash5'},
        ],
        metadata={
            'patient_id': 'P12345',
            'image_type': 'MRI',
            'department': 'Radiology'
        }
    )

    print(f"\nTransaction ID: {tx_id}")

    # Retrieve metadata
    metadata = client.get_image_metadata("IMG-2026-001")
    print(f"\nRetrieved metadata: {json.dumps(metadata, indent=2)}")

    # Verify image
    result = client.verify_image("IMG-2026-001", "abc123def456789...")
    print(f"\nVerification result: {result}")

    # Record access
    access_tx = client.record_access("IMG-2026-001", "DR-Smith", "view")
    print(f"\nAccess logged: {access_tx}")

    # List all images
    all_images = client.list_images()
    print(f"\nTotal images stored: {len(all_images)}")
