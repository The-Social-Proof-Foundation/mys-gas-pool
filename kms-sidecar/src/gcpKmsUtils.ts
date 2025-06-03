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
        
        // Parse DER format
        const derElement = new asn1ts.DERElement();
        derElement.fromBytes(publicKeyBytes);

        console.log('DER element parsed, checking structure...');
        console.log('DER tagClass:', derElement.tagClass);
        console.log('DER construction:', derElement.construction);
        console.log('DER tagNumber:', derElement.tagNumber);
        console.log('DER value type:', typeof derElement.value);
        console.log('DER value length:', derElement.value?.length);

        // Try to access the sequence components differently
        let components: any[] | undefined;
        
        // Method 1: Direct access to components (original approach)
        if ((derElement as any).components) {
            components = (derElement as any).components;
            console.log('Found components via direct access, length:', components?.length);
        } 
        // Method 2: Access via sequence property
        else if ((derElement as any).sequence) {
            components = (derElement as any).sequence;
            console.log('Found components via sequence property, length:', components?.length);
        }
        // Method 3: Parse as ASN.1 sequence manually
        else if (derElement.construction === asn1ts.ASN1Construction.constructed) {
            console.log('Attempting manual sequence parsing...');
            try {
                // Try to decode as a sequence
                const sequence = new asn1ts.DERElement();
                sequence.fromBytes(publicKeyBytes);
                if (sequence.value && sequence.value.length > 0) {
                    // Create new DER elements from the value
                    let offset = 0;
                    components = [];
                    while (offset < sequence.value.length) {
                        try {
                            const element = new asn1ts.DERElement();
                            const remainingBytes = sequence.value.slice(offset);
                            element.fromBytes(remainingBytes);
                            components.push(element);
                            // Use a more reliable way to calculate element length
                            const elementLength = (element as any).length || (element as any).encodedLength || remainingBytes.length;
                            offset += elementLength;
                            if (offset >= sequence.value.length) break;
                        } catch (e) {
                            console.log('Failed to parse element at offset', offset, ':', e);
                            break;
                        }
                    }
                    console.log('Manual parsing found', components?.length || 0, 'components');
                }
            } catch (e) {
                console.log('Manual sequence parsing failed:', e);
            }
        }

        if (!components || components.length === 0) {
            console.error('Could not find any components in DER structure');
            console.log('Raw DER bytes (first 20):', Array.from(publicKeyBytes.slice(0, 20)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
            
            // Try a completely different approach - raw byte parsing
            console.log('Attempting raw byte parsing of SECP256K1 public key...');
            try {
                // For SECP256K1 public keys, the DER structure typically ends with 65 bytes (0x04 + 32 + 32)
                // Let's try to find the public key bytes directly
                const derBytes = Array.from(publicKeyBytes);
                console.log('Full DER bytes:', derBytes.map(b => '0x' + b.toString(16).padStart(2, '0')).join(' '));
                
                // Look for the 0x04 prefix which indicates an uncompressed public key
                const pubkeyStartIndex = derBytes.findIndex((byte, index) => {
                    // Look for 0x04 followed by what should be 64 bytes
                    return byte === 0x04 && index + 64 < derBytes.length;
                });
                
                if (pubkeyStartIndex !== -1) {
                    console.log('Found potential public key at index:', pubkeyStartIndex);
                    const pubkeyBytes = publicKeyBytes.slice(pubkeyStartIndex, pubkeyStartIndex + 65);
                    console.log('Extracted public key bytes length:', pubkeyBytes.length);
                    
                    if (pubkeyBytes.length === 65 && pubkeyBytes[0] === 0x04) {
                        // Convert to bit array format expected by compressPublicKeyClamped
                        const rawPublicKey = new Uint8ClampedArray(520); // 65 bytes * 8 bits
                        for (let i = 0; i < 65; i++) {
                            for (let bit = 0; bit < 8; bit++) {
                                rawPublicKey[i * 8 + bit] = (pubkeyBytes[i] >> (7 - bit)) & 1;
                            }
                        }
                        
                        console.log('Successfully converted to bit array, compressing...');
                        const compressedKey = compressPublicKeyClamped(rawPublicKey);
                        const mysPublicKey = new Secp256k1PublicKey(compressedKey);
                        
                        console.log('SUCCESS! MySocial Public Key Address:', mysPublicKey.toMysAddress());
                        return mysPublicKey;
                    }
                }
            } catch (rawParseError) {
                console.log('Raw parsing also failed:', rawParseError);
            }
            
            throw new Error('Could not parse DER structure - no components found');
        }

        console.log('Found', components.length, 'components in DER structure');

        // Extract public key from ASN.1 DER structure
        if (
            derElement.tagClass === asn1ts.ASN1TagClass.universal &&
            derElement.construction === asn1ts.ASN1Construction.constructed &&
            components && components.length >= 2
        ) {
            const publicKeyElement = components[1];
            console.log('Public key element type:', typeof publicKeyElement);
            console.log('Public key element properties:', Object.keys(publicKeyElement));
            
            let rawPublicKey: Uint8ClampedArray | undefined;
            
            // Try different ways to access the bit string
            if (publicKeyElement.bitString) {
                rawPublicKey = publicKeyElement.bitString;
                console.log('Found bitString property');
            } else if ((publicKeyElement as any).value && (publicKeyElement as any).value instanceof Uint8Array) {
                // Convert Uint8Array to Uint8ClampedArray if needed
                const valueArray = (publicKeyElement as any).value as Uint8Array;
                rawPublicKey = new Uint8ClampedArray(valueArray.length * 8);
                // Convert bytes to bits
                for (let i = 0; i < valueArray.length; i++) {
                    for (let bit = 0; bit < 8; bit++) {
                        rawPublicKey[i * 8 + bit] = (valueArray[i] >> (7 - bit)) & 1;
                    }
                }
                console.log('Converted value to bit string');
            }

            if (!rawPublicKey) {
                console.error('Could not extract bit string from public key element');
                console.log('Available properties:', Object.keys(publicKeyElement));
                throw new Error('Could not extract public key from DER structure');
            }

            console.log('Raw public key bit string length:', rawPublicKey.length);
            const compressedKey = compressPublicKeyClamped(rawPublicKey);
            const mysPublicKey = new Secp256k1PublicKey(compressedKey);
            
            console.log('MySocial Public Key Address:', mysPublicKey.toMysAddress());
            return mysPublicKey;
        } else {
            const componentsLength = components ? components.length : 0;
            throw new Error(`Unexpected ASN.1 structure: tagClass=${derElement.tagClass}, construction=${derElement.construction}, components=${componentsLength}`);
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