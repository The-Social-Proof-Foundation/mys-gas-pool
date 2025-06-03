# MySocial Gas Pool - Railway Deployment Guide

This guide shows you how to deploy MySocial Gas Pool to Railway using Google Cloud KMS for transaction signing.

## Architecture

1. **Gas Pool Server** - Your existing Rust application
2. **Redis Database** - Railway Redis addon
3. **KMS Sidecar** - TypeScript service that calls Google Cloud KMS
4. **MySocial Fullnode** - Blockchain node

## Step 1: Google Cloud KMS Setup (Dashboard)

### 1.1 Create a New Project (or use existing)
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable billing for the project

### 1.2 Enable Cloud KMS API
1. Go to **APIs & Services > Library**
2. Search for "Cloud Key Management Service (KMS) API"
3. Click **Enable**

### 1.3 Create Key Ring and Key
1. Go to **Security > Key Management**
2. Click **Create Key Ring**
   - Name: `mys-gas-pool-keyring`
   - Location: `us-central1` (or your preferred region)
   - Click **Create**
3. Click **Create Key** in your new key ring
   - Name: `mys-sponsor-key`
   - Protection level: `Software`
   - Purpose: `Asymmetric sign`
   - Algorithm: `Elliptic Curve P-256 - SHA256 Digest`
   - Click **Create**

### 1.4 Create Service Account
1. Go to **IAM & Admin > Service Accounts**
2. Click **Create Service Account**
   - Name: `mys-gas-pool-kms`
   - Description: `MySocial Gas Pool KMS Service Account`
   - Click **Create and Continue**
3. Add role: `Cloud KMS CryptoKey Signer/Verifier`
4. Click **Done**
5. Click on your new service account
6. Go to **Keys** tab
7. Click **Add Key > Create New Key**
8. Choose **JSON** format
9. Download the key file (save as `gcp-service-account.json`)

## Step 2: KMS Sidecar (Already Created)

The TypeScript KMS sidecar has been created in the `kms-sidecar/` directory with:

- `package.json` - Dependencies and scripts
- `tsconfig.json` - TypeScript configuration  
- `src/index.ts` - Main server file
- `src/gcpKmsUtils.ts` - Google Cloud KMS utilities
- `Dockerfile` - Container configuration

To build and run locally:

```bash
cd kms-sidecar
npm install
npm run build
npm start
```

## Step 3: Deploy KMS Sidecar to Railway

```bash
cd kms-sidecar
railway login
railway init
railway up

# Set environment variables
railway variables set GOOGLE_CLOUD_PROJECT_ID=your-project-id
railway variables set KMS_LOCATION=us-central1
railway variables set KMS_KEYRING=mys-gas-pool-keyring
railway variables set KMS_KEY_NAME=mys-sponsor-key

# Upload service account key (base64 encoded)
cat ../gcp-service-account.json | base64 | railway variables set GOOGLE_APPLICATION_CREDENTIALS_JSON=-
```

## Step 4: Deploy Gas Pool to Railway

### 4.1 Update your existing `gas-station-config.yaml`:

```yaml
signer-config:
  sidecar:
    sidecar_url: "${KMS_SIDECAR_URL}"
rpc-host-ip: 0.0.0.0
rpc-port: ${PORT:-9527}
metrics-port: 9184
gas-pool-config:
  redis:
    redis_url: "${REDIS_URL}"
fullnode-url: "${FULLNODE_URL}"
coin-init-config:
  target-init-balance: 100000000
  refresh-interval-sec: 86400
daily-gas-usage-cap: 1500000000000
```

### 4.2 Deploy Gas Pool

```bash
# In your gas pool project root
railway login
railway init mys-gas-pool
railway add redis

# Set environment variables
railway variables set GAS_STATION_AUTH=your-secure-random-token
railway variables set KMS_SIDECAR_URL=https://your-kms-sidecar.railway.app
railway variables set FULLNODE_URL=https://fullnode.mainnet.mysocial.network:443

# Deploy
railway up
```

## Step 5: Fund and Test

1. Get sponsor address: `curl https://your-kms-sidecar.railway.app/get-pubkey-address`
2. Send MySocial coins to that address
3. Test: `curl https://your-gas-pool.railway.app/`

The TypeScript sidecar implements the exact interface your existing `SidecarTxSigner` expects:
- `GET /get-pubkey-address` → `{ mysPubkeyAddress: "0x..." }`
- `POST /sign-transaction` → `{ signature: "base64..." }` 