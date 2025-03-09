# BTC-Stacks Bridge Contract

A secure and decentralized bridge contract facilitating cross-chain asset transfers between Bitcoin and Stacks blockchains. Implements multi-signature validator consensus, rate limiting, and robust security mechanisms for trustless operations.

## Features

- **Bi-Directional Asset Transfers**  
  Enable seamless movement of assets between Bitcoin and Stacks networks through standardized deposit/withdrawal flows.

- **Multi-Signature Validator Consensus**  
  Requires `VALIDATOR-THRESHOLD` confirmations from independent validators to process transactions.

- **Dynamic Validator Management**  
  Admin-controlled validator set with minimum validator enforcement (`MIN-VALIDATORS=3`).

- **Risk Mitigation**

  - Deposit amount validation (`MIN-DEPOSIT-AMOUNT=100,000`, `MAX-DEPOSIT-AMOUNT=1,000,000,000` μSTX)
  - Bitcoin address format checks
  - Transaction hash validation
  - Daily withdrawal limits (`MAX-DAILY-WITHDRAWAL-AMOUNT=10,000,000,000` μSTX)
  - Rate limiting (5 withdrawals/user/24h)

- **Operational Controls**
  - Emergency pause/resume functionality
  - Admin role transfer protocol
  - Balance recovery through emergency withdrawals

## Contract Architecture

### Core Components

| Component                | Type     | Description                                                                   |
| ------------------------ | -------- | ----------------------------------------------------------------------------- |
| `bridgeable-token-trait` | Trait    | Standard interface for bridged tokens (transfer, balance queries)             |
| `deposits`               | Data Map | Tracks cross-chain deposits with confirmation status and validator signatures |
| `validators`             | Data Map | Stores authorized validator addresses                                         |
| `bridge-balances`        | Data Map | Maintains user balances of bridged assets                                     |

### Security Parameters

| Parameter                | Value | Description                                      |
| ------------------------ | ----- | ------------------------------------------------ |
| `REQUIRED-CONFIRMATIONS` | 6     | Bitcoin network confirmations required           |
| `VALIDATOR-THRESHOLD`    | 3     | Validator signatures needed for deposit approval |
| `RATE-LIMIT-WINDOW`      | 144   | Blocks (≈24h) for rate limit windows             |

## Key Functions

### Administrative Operations

- `initialize-bridge`  
  Activates bridge operations (deployer only)
- `pause-bridge/resume-bridge`  
  Emergency circuit breakers (admin only)

- `add-validator/remove-validator`  
  Manage validator set with minimum count enforcement

- `propose-admin-change/accept-admin-role`  
  Timelocked admin role transfer protocol

### Validator Operations

- `initiate-deposit`  
  Start deposit process with BTC transaction details

- `update-confirmations`  
  Adjust Bitcoin transaction confirmation count

- `confirm-deposit`  
  Provide validator signature to approve deposit

### User Operations

- `withdraw`  
  Convert bridged assets to Bitcoin (requires BTC address validation)

- `emergency-withdraw`  
  Admin-initiated balance recovery (bypass normal limits)

### Monitoring & Queries

- `get-deposit`  
  Retrieve deposit status by Bitcoin TX hash

- `get-bridge-balance`  
  Check user's bridged asset balance

- `get-validator-status`  
  Verify validator authorization status

## Error Handling

| Error Code                          | Description                                |
| ----------------------------------- | ------------------------------------------ |
| `ERROR-BRIDGE-PAUSED`               | Bridge operations temporarily suspended    |
| `ERROR-INVALID-SIGNATURE`           | Malformed or duplicate validator signature |
| `ERROR-VALIDATOR-THRESHOLD-NOT-MET` | Insufficient validator approvals           |
| `ERROR-MAX-DAILY-LIMIT-REACHED`     | Daily withdrawal cap exceeded              |
| `ERROR-INVALID-BTC-ADDRESS`         | Malformed Bitcoin address detected         |

## Security Model

### Consensus Mechanism

Deposit finalization requires:

1. Bitcoin transaction with ≥6 confirmations
2. Unique signatures from ≥3 validators
3. Rate limit compliance

### Input Validation

- Principal address format checks
- BTC address length/format verification (33/34 bytes)
- TX hash validation (32-byte format)
- Signature format enforcement (65-byte ECDSA)

### Economic Limits

- Individual user rate limits
  - 5 withdrawals per 24h window
  - Amount-based throttling
- System-wide daily withdrawal cap (10B μSTX)

## Testing Protocol

Recommended test coverage areas:

**Validation Tests**

- Invalid signature rejection
- Unauthorized access attempts
- Malformed address handling

**Operational Tests**

- Multi-validator deposit confirmation flow
- Daily withdrawal limit enforcement
- Bridge pause/resume functionality

**Edge Cases**

- Validator threshold boundary conditions
- Cross-window rate limit transitions
- Admin role transfer expiration
