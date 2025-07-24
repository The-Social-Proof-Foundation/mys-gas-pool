import { KeyManagementServiceClient } from '@google-cloud/kms';
import { Secp256k1PublicKey } from '@socialproof/mys/keypairs/secp256k1';
import { fromB64, toB64 } from '@socialproof/mys/utils';
import {
    toSerializedSignature,
    SIGNATURE_FLAG_TO_SCHEME,
    SignatureScheme,
    SignatureFlag,
    messageWithIntent,
} from '@socialproof/mys/cryptography';
import { blake2b } from '@noble/hashes/blake2b';
import { secp256k1 } from '@noble/curves/secp256k1';

// Compress uncompressed public key from raw bytes
function compressPublicKey(uncompressedKey: Uint8Array): Uint8Array {
    if (uncompressedKey.length !== 65) {
        throw new Error(`Unexpected length for an uncompressed public key: ${uncompressedKey.length}, expected 65`);
    }

    // Check if the first byte is 0x04 (uncompressed format)
    if (uncompressedKey[0] !== 0x04) {
        throw new Error(`Public key does not start with 0x04, starts with: 0x${uncompressedKey[0].toString(16).padStart(2, '0')}`);
    }

    // Extract X-coordinate (bytes 1-32)
    const xCoord = uncompressedKey.slice(1, 33);
    
    // Extract Y-coordinate (bytes 33-64) 
    const yCoord = uncompressedKey.slice(33, 65);
    
    // Determine parity byte for compressed format
    const yLastByte = yCoord[31]; // Last byte of Y coordinate
    const parityByte = yLastByte % 2 === 0 ? 0x02 : 0x03;

    return new Uint8Array([parityByte, ...xCoord]);
}

// Create Google Cloud KMS client
function createGCPKMSClient(): KeyManagementServiceClient {
    // Option 1: Base64 encoded JSON credentials (preferred for Railway)
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
        try {
            const credentialsJson = Buffer.from(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON, 'base64').toString('utf-8');
            const credentials = JSON.parse(credentialsJson);
            return new KeyManagementServiceClient({
                credentials: credentials,
                projectId: credentials.project_id
            });
        } catch (error) {
            console.error('Failed to parse base64 credentials:', error);
            throw new Error(`Invalid GOOGLE_APPLICATION_CREDENTIALS_JSON format: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    
    // Option 2: File path (for local development)
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
        return new KeyManagementServiceClient({
            keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
        });
    }
    
    // Option 3: Default credentials (fallback)
    return new KeyManagementServiceClient();
}

export async function getPublicKey(keyPath: string): Promise<Secp256k1PublicKey | undefined> {
    const client = createGCPKMSClient();

    try {
        const [publicKeyResponse] = await client.getPublicKey({ name: keyPath });
        
        if (!publicKeyResponse.pem) {
            throw new Error('No PEM public key found in response');
        }

        // Parse PEM format to get DER bytes
        const pemContent = publicKeyResponse.pem
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\n/g, '');
        
        const publicKeyBytes = Buffer.from(pemContent, 'base64');
        
        // Find the BIT STRING (tag 0x03) containing the public key
        let bitStringIndex = -1;
        for (let i = 0; i < publicKeyBytes.length - 1; i++) {
            if (publicKeyBytes[i] === 0x03) {
                // Found BIT STRING tag, next byte should be length
                const length = publicKeyBytes[i + 1];
                if (length === 0x42) { // 66 bytes for SECP256K1 (1 + 1 + 64)
                    bitStringIndex = i;
                    break;
                }
            }
        }
        
        if (bitStringIndex === -1) {
            throw new Error('Could not find BIT STRING with expected length in DER structure');
        }
        
        // Extract the bit string content
        // Skip: tag(1) + length(1) + unused_bits(1) = 3 bytes
        const publicKeyStart = bitStringIndex + 3;
        const publicKeyEnd = publicKeyStart + 65; // 1 + 32 + 32 bytes
        
        if (publicKeyEnd > publicKeyBytes.length) {
            throw new Error('DER structure too short for public key data');
        }
        
        const uncompressedKey = publicKeyBytes.slice(publicKeyStart, publicKeyEnd);
        const compressedKey = compressPublicKey(uncompressedKey);
        const mysPublicKey = new Secp256k1PublicKey(compressedKey);
        
        return mysPublicKey;
        
    } catch (error) {
        console.error('Error during get public key:', error);
        return undefined;
    }
}

// Convert DER signature to concatenated format for MySocial
function getConcatenatedSignature(signature: Uint8Array): Uint8Array {
    // DER signature format for ECDSA:
    // 30 [total-length] 02 [R-length] [R] 02 [S-length] [S]
    
    if (signature[0] !== 0x30) {
        throw new Error('Invalid DER signature: does not start with SEQUENCE tag');
    }
    
    let offset = 2; // Skip SEQUENCE tag and length
    
    // Parse R value
    if (signature[offset] !== 0x02) {
        throw new Error('Invalid DER signature: R value does not start with INTEGER tag');
    }
    
    const rLength = signature[offset + 1];
    offset += 2; // Skip INTEGER tag and length
    
    let rBytes = signature.slice(offset, offset + rLength);
    offset += rLength;
    
    // Remove leading zero if present (DER encoding adds it for positive numbers)
    if (rBytes[0] === 0x00 && rBytes.length > 32) {
        rBytes = rBytes.slice(1);
    }
    
    // Pad to 32 bytes if needed
    if (rBytes.length < 32) {
        const padded = new Uint8Array(32);
        padded.set(rBytes, 32 - rBytes.length);
        rBytes = padded;
    }
    
    // Parse S value
    if (signature[offset] !== 0x02) {
        throw new Error('Invalid DER signature: S value does not start with INTEGER tag');
    }
    
    const sLength = signature[offset + 1];
    offset += 2; // Skip INTEGER tag and length
    
    let sBytes = signature.slice(offset, offset + sLength);
    
    // Remove leading zero if present
    if (sBytes[0] === 0x00 && sBytes.length > 32) {
        sBytes = sBytes.slice(1);
    }
    
    // Pad to 32 bytes if needed
    if (sBytes.length < 32) {
        const padded = new Uint8Array(32);
        padded.set(sBytes, 32 - sBytes.length);
        sBytes = padded;
    }
    
    // Convert to BigInt for secp256k1 library
    const r = BigInt('0x' + Array.from(rBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    const s = BigInt('0x' + Array.from(sBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    const secp256k1Sig = new secp256k1.Signature(r, s);
    
    return secp256k1Sig.normalizeS().toCompactRawBytes();
}

// Create serialized signature for MySocial
async function getSerializedSignature(
    signature: Uint8Array,
    mysPublicKey: Secp256k1PublicKey
): Promise<string> {
    // For MySocial network, always use Secp256k1 scheme with flag 0x01
    const signatureScheme: SignatureScheme = 'Secp256k1';
    
    console.log('Creating signature with scheme:', signatureScheme);
    console.log('Public key flag:', mysPublicKey.flag());
    console.log('Public key bytes length:', mysPublicKey.toRawBytes().length);
    
    return toSerializedSignature({
        signatureScheme,
        signature,
        publicKey: mysPublicKey,
    });
}

export async function signAndVerify(txBytes: Uint8Array, keyPath: string): Promise<string | undefined> {
    const client = createGCPKMSClient();
    
    try {
        console.log('Starting signature process for transaction bytes length:', txBytes.length);
        
        // Add intent message to transaction bytes
        const intentMessage = messageWithIntent('TransactionData' as any, txBytes);
        console.log('Intent message created, length:', intentMessage.length);
        
        // Create digest using blake2b hash
        const digest = blake2b(intentMessage, { dkLen: 32 });
        console.log('Digest created, length:', digest.length);
        
        // Sign the digest using Google Cloud KMS
        const [signResponse] = await client.asymmetricSign({
            name: keyPath,
            data: digest,
        });
        
        if (!signResponse.signature) {
            throw new Error('No signature returned from KMS');
        }
        
        const signature = signResponse.signature instanceof Uint8Array 
            ? signResponse.signature 
            : new Uint8Array(Buffer.from(signResponse.signature as string, 'base64'));
        
        console.log('Raw KMS signature length:', signature.length);
        
        // Get the public key
        const originalPublicKey = await getPublicKey(keyPath);
        if (!originalPublicKey) {
            throw new Error('Could not retrieve public key');
        }
        
        console.log('Public key retrieved successfully');
        console.log('Public key address:', originalPublicKey.toMysAddress());
        
        // Convert DER signature to concatenated format
        const concatenatedSignature = getConcatenatedSignature(signature);
        console.log('Concatenated signature length:', concatenatedSignature.length);
        
        // Create serialized signature for MySocial
        const serializedSignature = await getSerializedSignature(
            concatenatedSignature,
            originalPublicKey
        );
        
        console.log('Serialized signature created, length:', serializedSignature.length);
        
        // Verify signature with MySocial
        const isValid = await originalPublicKey.verifyTransaction(
            txBytes,
            serializedSignature
        );
        
        console.log('Signature verification result:', isValid);
        
        if (!isValid) {
            console.error('Signature verification failed!');
            return undefined;
        }
        
        return serializedSignature;
    } catch (error) {
        console.error('Error during sign/verify:', error);
        console.error('Error stack:', error instanceof Error ? error.stack : 'No stack trace');
        return undefined;
    }
} 