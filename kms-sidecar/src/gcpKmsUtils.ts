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
import * as asn1ts from 'asn1-ts';

// Helper function to convert bits to bytes for DER parsing
function bitsToBytes(bitsArray: Uint8ClampedArray): Uint8Array {
    const bytes = new Uint8Array(65);
    for (let i = 0; i < 520; i++) {
        if (bitsArray[i] === 1) {
            bytes[Math.floor(i / 8)] |= 1 << (7 - (i % 8));
        }
    }
    return bytes;
}

// Compress uncompressed public key from DER format
function compressPublicKeyClamped(uncompressedKey: Uint8ClampedArray): Uint8Array {
    if (uncompressedKey.length !== 520) {
        throw new Error('Unexpected length for an uncompressed public key');
    }

    // Convert bits to bytes
    const uncompressedBytes = bitsToBytes(uncompressedKey);

    // Check if the first byte is 0x04
    if (uncompressedBytes[0] !== 0x04) {
        throw new Error('Public key does not start with 0x04');
    }

    // Extract X-Coordinate (skip the first byte, which should be 0x04)
    const xCoord = uncompressedBytes.slice(1, 33);

    // Determine parity byte for y coordinate
    const yCoordLastByte = uncompressedBytes[64];
    const parityByte = yCoordLastByte % 2 === 0 ? 0x02 : 0x03;

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
            throw new Error('Invalid GOOGLE_APPLICATION_CREDENTIALS_JSON format');
        }
    }
    
    // Option 2: File path (for local development)
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
        return new KeyManagementServiceClient({
            keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
        });
    }
    
    // Option 3: Default credentials (fallback)
    console.warn('No explicit credentials found, using default application credentials');
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
        
        // Parse DER format
        const derElement = new asn1ts.DERElement();
        derElement.fromBytes(publicKeyBytes);

        // Extract public key from ASN.1 DER structure
        if (
            derElement.tagClass === asn1ts.ASN1TagClass.universal &&
            derElement.construction === asn1ts.ASN1Construction.constructed
        ) {
            const components = (derElement as any).components;
            const publicKeyElement = components[1];
            const rawPublicKey = publicKeyElement.bitString;

            if (!rawPublicKey) {
                throw new Error('Could not extract public key from DER structure');
            }

            const compressedKey = compressPublicKeyClamped(rawPublicKey);
            const mysPublicKey = new Secp256k1PublicKey(compressedKey);
            
            console.log('MySocial Public Key Address:', mysPublicKey.toMysAddress());
            return mysPublicKey;
        } else {
            throw new Error('Unexpected ASN.1 structure');
        }
    } catch (error) {
        console.error('Error during get public key:', error);
        return undefined;
    }
}

// Convert DER signature to concatenated format for MySocial
function getConcatenatedSignature(signature: Uint8Array): Uint8Array {
    const derElement = new asn1ts.DERElement();
    derElement.fromBytes(signature);
    
    const derJsonData = (derElement as any).toJSON() as { value: string }[];
    
    const rValue = derJsonData[0];
    const sValue = derJsonData[1];
    
    const rString = String(rValue);
    const sString = String(sValue);
    
    const secp256k1Sig = new secp256k1.Signature(
        BigInt(rString),
        BigInt(sString)
    );
    
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