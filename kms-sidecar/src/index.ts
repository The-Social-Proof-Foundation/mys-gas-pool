import 'dotenv/config';
import express, { Request, Response } from 'express';
import { fromB64 } from '@socialproof/mys/utils';
import { getPublicKey, signAndVerify } from './gcpKmsUtils';

async function main() {
    const app = express();
    app.use(express.json());
    
    const port = process.env.PORT || 3000;
    
    // Environment variables for Google Cloud KMS
    const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT_ID;
    const LOCATION = process.env.KMS_LOCATION || 'us-central1';
    const KEYRING = process.env.KMS_KEYRING || 'mys-gas-pool-keyring';
    const KEY_NAME = process.env.KMS_KEY_NAME || 'mys-sponsor-key';
    
    const keyPath = `projects/${PROJECT_ID}/locations/${LOCATION}/keyRings/${KEYRING}/cryptoKeys/${KEY_NAME}/cryptoKeyVersions/1`;
    
    // Health check endpoint
    app.get('/', (req: Request, res: Response) => {
        res.json({ status: 'healthy', service: 'MySocial Gas Pool GCP KMS Sidecar' });
    });
    
    // Get public key and address - matches interface expected by SidecarTxSigner
    app.get('/get-pubkey-address', async (req: Request, res: Response) => {
        try {
            if (!PROJECT_ID) {
                console.error('GOOGLE_CLOUD_PROJECT_ID is required but not set');
                return res.status(500).json({ 
                    error: 'Failed to get public key', 
                    details: 'GOOGLE_CLOUD_PROJECT_ID environment variable is required' 
                });
            }
            
            const publicKey = await getPublicKey(keyPath);
            
            if (!publicKey) {
                console.error('getPublicKey returned null/undefined');
                return res.status(500).json({ 
                    error: 'Failed to get public key',
                    details: 'Check server logs for detailed error information'
                });
            }
            
            const mysPubkeyAddress = publicKey.toMysAddress();
            res.json({ mysPubkeyAddress });
        } catch (error) {
            console.error('Error getting public key:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            res.status(500).json({ 
                error: 'Internal server error',
                details: errorMessage
            });
        }
    });
    
    // Sign transaction - matches interface expected by SidecarTxSigner
    app.post('/sign-transaction', async (req: Request, res: Response) => {
        try {
            const { txBytes } = req.body;
            
            if (!txBytes) {
                return res.status(400).json({ error: 'Missing transaction bytes' });
            }
            
            console.log('Received sign-transaction request, txBytes length:', txBytes.length);
            
            const txBytesArray = fromB64(txBytes);
            const signature = await signAndVerify(txBytesArray, keyPath);
            
            console.log('signAndVerify returned:', signature ? `signature of length ${signature.length}` : 'undefined');
            
            if (!signature) {
                console.error('signAndVerify returned undefined or empty signature');
                return res.status(500).json({ error: 'Failed to sign transaction' });
            }
            
            console.log('Sending successful response with signature');
            res.json({ signature });
        } catch (error) {
            console.error('Error signing transaction:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
    
    app.listen(port, () => {
        console.log(`GCP KMS Sidecar listening on port ${port}`);
    });
}

main().catch(console.error); 