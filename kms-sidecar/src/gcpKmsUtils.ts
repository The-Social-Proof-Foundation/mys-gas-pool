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
    console.log('=== COMPRESS PUBLIC KEY DEBUG ===');
    console.log('Input bytes length:', uncompressedKey.length);
    console.log('First 10 bytes:', Array.from(uncompressedKey.slice(0, 10)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
    console.log('Last 5 bytes:', Array.from(uncompressedKey.slice(-5)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));

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

    console.log('X coordinate:', Array.from(xCoord).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('Y coordinate last byte:', yLastByte.toString(16).padStart(2, '0'));
    console.log('Parity byte:', parityByte.toString(16).padStart(2, '0'));

    return new Uint8Array([parityByte, ...xCoord]);
}

// Create Google Cloud KMS client
function createGCPKMSClient(): KeyManagementServiceClient {
    console.log('=== CREATING GCP KMS CLIENT ===');
    
    // Option 1: Base64 encoded JSON credentials (preferred for Railway)
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
        console.log('Using GOOGLE_APPLICATION_CREDENTIALS_JSON');
        try {
            const credentialsJson = Buffer.from(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON, 'base64').toString('utf-8');
            const credentials = JSON.parse(credentialsJson);
            console.log('Credentials parsed successfully, project_id:', credentials.project_id);
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
        console.log('Using GOOGLE_APPLICATION_CREDENTIALS file path:', process.env.GOOGLE_APPLICATION_CREDENTIALS);
        return new KeyManagementServiceClient({
            keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
        });
    }
    
    // Option 3: Default credentials (fallback)
    console.warn('No explicit credentials found, using default application credentials');
    console.log('This may fail in production environments like Railway');
    return new KeyManagementServiceClient();
}

export async function getPublicKey(keyPath: string): Promise<Secp256k1PublicKey | undefined> {
    const client = createGCPKMSClient();

    try {
        console.log('Attempting to get public key for path:', keyPath);
        const [publicKeyResponse] = await client.getPublicKey({ name: keyPath });
        
        console.log('KMS Response received, checking for PEM...');
        if (!publicKeyResponse.pem) {
            console.error('No PEM public key found in KMS response');
            throw new Error('No PEM public key found in response');
        }

        console.log('PEM found, parsing...');
        // Parse PEM format to get DER bytes
        const pemContent = publicKeyResponse.pem
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\n/g, '');
        
        console.log('PEM content length:', pemContent.length);
        const publicKeyBytes = Buffer.from(pemContent, 'base64');
        console.log('DER bytes length:', publicKeyBytes.length);
        console.log('DER bytes (hex):', publicKeyBytes.toString('hex'));
        
        // According to RFC 5280 and X.509 standards, for SECP256K1 public keys:
        // The DER structure is: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING }
        // The BIT STRING contains: unused_bits_byte + 0x04 + X_coord(32) + Y_coord(32)
        
        // For SECP256K1, the OID is 1.3.132.0.10 and the total structure should be:
        // 30 56 (SEQUENCE, 86 bytes)
        //   30 10 (SEQUENCE, 16 bytes) - AlgorithmIdentifier  
        //     06 07 2A8648CE3D020106 (OID for id-ecPublicKey)
        //     06 05 2B8104000A (OID for secp256k1: 1.3.132.0.10)
        //   03 42 (BIT STRING, 66 bytes)
        //     00 (unused bits)
        //     04 (uncompressed point indicator)
        //     [32 bytes X coordinate]
        //     [32 bytes Y coordinate]
        
        // Find the BIT STRING (tag 0x03)
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
        console.log('Extracted uncompressed key length:', uncompressedKey.length);
        console.log('Uncompressed key (hex):', Array.from(uncompressedKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        const compressedKey = compressPublicKey(uncompressedKey);
        const mysPublicKey = new Secp256k1PublicKey(compressedKey);
        
        console.log('SUCCESS! MySocial Public Key Address:', mysPublicKey.toMysAddress());
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
    const flag = mysPublicKey.flag();
    
    // Check if flag is one of the allowed values and cast to SignatureFlag
    const allowedFlags: SignatureFlag[] = [0, 1, 2, 3, 5];
    const isAllowedFlag = allowedFlags.includes(flag as SignatureFlag);
    
    const signatureScheme: SignatureScheme = isAllowedFlag
        ? SIGNATURE_FLAG_TO_SCHEME[flag as SignatureFlag]
        : 'Secp256k1';
    
    return toSerializedSignature({
        signatureScheme,
        signature,
        publicKey: mysPublicKey,
    });
}

export async function signAndVerify(txBytes: Uint8Array, keyPath: string): Promise<string | undefined> {
    const client = createGCPKMSClient();
    
    // Add intent message to transaction bytes
    const intentMessage = messageWithIntent('TransactionData' as any, txBytes);
    
    // Create digest using blake2b hash
    const digest = blake2b(intentMessage, { dkLen: 32 });
    
    console.log('TX Bytes:', toB64(txBytes));
    console.log('Digest:', toB64(digest));
    
    try {
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
        
        // Get the public key
        const originalPublicKey = await getPublicKey(keyPath);
        if (!originalPublicKey) {
            throw new Error('Could not retrieve public key');
        }
        
        // Convert DER signature to concatenated format
        const concatenatedSignature = getConcatenatedSignature(signature);
        
        // Create serialized signature for MySocial
        const serializedSignature = await getSerializedSignature(
            concatenatedSignature,
            originalPublicKey
        );
        
        console.log('Serialized Signature:', serializedSignature);
        
        // Verify signature with MySocial
        console.log('Verifying MySocial Signature against TX');
        const isValid = await originalPublicKey.verifyTransaction(
            txBytes,
            serializedSignature
        );
        console.log('MySocial Signature valid:', isValid);
        
        return serializedSignature;
    } catch (error) {
        console.error('Error during sign/verify:', error);
        return undefined;
    }
} 