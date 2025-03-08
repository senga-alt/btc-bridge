;; title: btc-bridge-contract
;; summary: Enables secure cross-chain transfers between Bitcoin and Stacks networks
;; description: Facilitates secure asset transfers between Bitcoin and Stacks blockchains,
;; handling deposits, withdrawals, and validator management with robust security checks.


;; traits
(define-trait bridgeable-token-trait
    (
        (transfer (uint principal principal) (response bool uint))
        (get-balance (principal) (response uint uint))
    )
)

;; Error codes
(define-constant ERROR-NOT-AUTHORIZED u1000)
(define-constant ERROR-INVALID-AMOUNT u1001)
(define-constant ERROR-INSUFFICIENT-BALANCE u1002)
(define-constant ERROR-INVALID-BRIDGE-STATUS u1003)
(define-constant ERROR-INVALID-SIGNATURE u1004)
(define-constant ERROR-ALREADY-PROCESSED u1005)
(define-constant ERROR-BRIDGE-PAUSED u1006)
(define-constant ERROR-INVALID-VALIDATOR-ADDRESS u1007)
(define-constant ERROR-INVALID-RECIPIENT-ADDRESS u1008)
(define-constant ERROR-INVALID-BTC-ADDRESS u1009)
(define-constant ERROR-INVALID-TX-HASH u1010)
(define-constant ERROR-INVALID-SIGNATURE-FORMAT u1011)
(define-constant ERROR-INSUFFICIENT-VALIDATORS u1012)
(define-constant ERROR-DUPLICATE-SIGNATURE u1013)
(define-constant ERROR-VALIDATOR-THRESHOLD-NOT-MET u1014)
(define-constant ERROR-INVALID-TIMESTAMP u1015)
(define-constant ERROR-MAX-DAILY-LIMIT-REACHED u1016)
(define-constant ERROR-RATE-LIMIT-EXCEEDED u1017)

;; Constants
(define-constant CONTRACT-DEPLOYER tx-sender)
(define-constant MIN-DEPOSIT-AMOUNT u100000)
(define-constant MAX-DEPOSIT-AMOUNT u1000000000)
(define-constant REQUIRED-CONFIRMATIONS u6)
(define-constant VALIDATOR-THRESHOLD u3)  ;; Minimum validators required for consensus
(define-constant MAX-DAILY-WITHDRAWAL-AMOUNT u10000000000) ;; 10 billion microSTX daily limit
(define-constant RATE-LIMIT-WINDOW u144) ;; Approximately 24 hours in Stacks blocks
(define-constant MIN-VALIDATORS u3) ;; Minimum required validators to operate

;; data vars
(define-data-var bridge-paused bool false)
(define-data-var total-bridged-amount uint u0)
(define-data-var last-processed-height uint u0)
(define-data-var validator-count uint u0)
(define-data-var admin principal tx-sender)
(define-data-var daily-withdrawal-total uint u0)
(define-data-var daily-withdrawal-reset-height uint u0)

;; data maps
(define-map deposits 
    { tx-hash: (buff 32) }
    {
        amount: uint,
        recipient: principal,
        processed: bool,
        confirmations: uint,
        timestamp: uint,
        btc-sender: (buff 33),
        validator-signatures: uint
    }
)

(define-map validators principal bool)
(define-map validator-signatures
    { tx-hash: (buff 32), validator: principal }
    { signature: (buff 65), timestamp: uint }
)

(define-map bridge-balances principal uint)

(define-map user-withdrawal-limits
    { user: principal, window-start: uint }
    { total-amount: uint, request-count: uint }
)

(define-map pending-admin-change
    { proposed-by: principal }
    { new-admin: principal, expiration-height: uint }
)

;; Authorization functions
(define-private (is-admin)
    (is-eq tx-sender (var-get admin))
)

(define-private (is-contract-owner)
    (is-eq tx-sender CONTRACT-DEPLOYER)
)

;; Rate limiting functions
(define-private (check-rate-limit (user principal) (amount uint))
    (let
        (
            (current-block stacks-block-height)
            (window-start (- current-block (mod current-block RATE-LIMIT-WINDOW)))
            (user-limits (default-to
                { total-amount: u0, request-count: u0 }
                (map-get? user-withdrawal-limits { user: user, window-start: window-start })
            ))
            (updated-total (+ (get total-amount user-limits) amount))
            (updated-count (+ (get request-count user-limits) u1))
        )
        
        ;; Allow 5 withdrawals per window
        (asserts! (<= updated-count u5) (err ERROR-RATE-LIMIT-EXCEEDED))
        
        ;; Update user limits
        (map-set user-withdrawal-limits
            { user: user, window-start: window-start }
            { total-amount: updated-total, request-count: updated-count }
        )
        
        (ok true)
    )
)

(define-private (check-daily-withdrawal-limit (amount uint))
    (let
        (
            (current-block stacks-block-height)
            (reset-height (var-get daily-withdrawal-reset-height))
            (current-total (var-get daily-withdrawal-total))
        )
        
        ;; Check if we need to reset the daily counter
        (if (> current-block (+ reset-height RATE-LIMIT-WINDOW))
            (begin
                (var-set daily-withdrawal-total amount)
                (var-set daily-withdrawal-reset-height current-block)
            )
            (var-set daily-withdrawal-total (+ current-total amount))
        )
        
        ;; Check if the limit would be exceeded
        (asserts! (<= (var-get daily-withdrawal-total) MAX-DAILY-WITHDRAWAL-AMOUNT)
            (err ERROR-MAX-DAILY-LIMIT-REACHED))
        
        (ok true)
    )
)

;; Public functions
;; Initializes the bridge by setting the paused state to false. Only the contract deployer can call this function.
(define-public (initialize-bridge)
    (begin
        (asserts! (is-contract-owner) (err ERROR-NOT-AUTHORIZED))
        (var-set bridge-paused false)
        (var-set daily-withdrawal-reset-height stacks-block-height)
        (ok true)
    )
)