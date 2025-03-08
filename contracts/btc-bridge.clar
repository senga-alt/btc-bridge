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

;; Pauses the bridge. Only the admin can call this function.
(define-public (pause-bridge)
    (begin
        (asserts! (is-admin) (err ERROR-NOT-AUTHORIZED))
        (var-set bridge-paused true)
        (ok true)
    )
)

;; Resumes the bridge if it is paused. Only the admin can call this function.
(define-public (resume-bridge)
    (begin
        (asserts! (is-admin) (err ERROR-NOT-AUTHORIZED))
        (asserts! (var-get bridge-paused) (err ERROR-INVALID-BRIDGE-STATUS))
        (asserts! (>= (var-get validator-count) MIN-VALIDATORS) (err ERROR-INSUFFICIENT-VALIDATORS))
        (var-set bridge-paused false)
        (ok true)
    )
)

;; Proposes a new admin for the contract
(define-public (propose-admin-change (new-admin principal))
    (begin
        (asserts! (is-admin) (err ERROR-NOT-AUTHORIZED))
        (asserts! (is-valid-principal new-admin) (err ERROR-INVALID-RECIPIENT-ADDRESS))
        
        (map-set pending-admin-change
            { proposed-by: tx-sender }
            { new-admin: new-admin, expiration-height: (+ stacks-block-height u144) }
        )
        
        (ok true)
    )
)

;; Accepts a pending admin change
(define-public (accept-admin-role)
    (let
        (
            (pending-change (unwrap! (map-get? pending-admin-change { proposed-by: (var-get admin) }) 
                            (err ERROR-NOT-AUTHORIZED)))
            (expiration (get expiration-height pending-change))
        )
        
        (asserts! (is-eq tx-sender (get new-admin pending-change)) (err ERROR-NOT-AUTHORIZED))
        (asserts! (<= stacks-block-height expiration) (err ERROR-INVALID-TIMESTAMP))
        
        (var-set admin tx-sender)
        
        ;; Clear the pending change
        (map-delete pending-admin-change { proposed-by: (var-get admin) })
        
        (ok true)
    )
)

;; Adds a validator to the bridge. Only the admin can call this function.
(define-public (add-validator (validator principal))
    (begin
        (asserts! (is-admin) (err ERROR-NOT-AUTHORIZED))
        (asserts! (is-valid-principal validator) (err ERROR-INVALID-VALIDATOR-ADDRESS))
        (asserts! (not (default-to false (map-get? validators validator))) (err ERROR-ALREADY-PROCESSED))
        
        (map-set validators validator true)
        (var-set validator-count (+ (var-get validator-count) u1))
        
        (ok true)
    )
)

;; Removes a validator from the bridge. Only the admin can call this function.
(define-public (remove-validator (validator principal))
    (begin
        (asserts! (is-admin) (err ERROR-NOT-AUTHORIZED))
        (asserts! (is-valid-principal validator) (err ERROR-INVALID-VALIDATOR-ADDRESS))
        (asserts! (default-to false (map-get? validators validator)) (err ERROR-INVALID-VALIDATOR-ADDRESS))
        (asserts! (> (var-get validator-count) MIN-VALIDATORS) (err ERROR-INSUFFICIENT-VALIDATORS))
        
        (map-set validators validator false)
        (var-set validator-count (- (var-get validator-count) u1))
        
        (ok true)
    )
)

;; Initiates a deposit into the bridge. Validators must call this function.
(define-public (initiate-deposit 
    (tx-hash (buff 32)) 
    (amount uint) 
    (recipient principal)
    (btc-sender (buff 33))
)
    (begin
        (asserts! (not (var-get bridge-paused)) (err ERROR-BRIDGE-PAUSED))
        (asserts! (validate-deposit-amount amount) (err ERROR-INVALID-AMOUNT))
        (asserts! (get-validator-status tx-sender) (err ERROR-NOT-AUTHORIZED))
        (asserts! (is-valid-tx-hash tx-hash) (err ERROR-INVALID-TX-HASH))
        (asserts! (is-none (map-get? deposits {tx-hash: tx-hash})) (err ERROR-ALREADY-PROCESSED))
        (asserts! (is-valid-principal recipient) (err ERROR-INVALID-RECIPIENT-ADDRESS))
        (asserts! (is-valid-btc-address btc-sender) (err ERROR-INVALID-BTC-ADDRESS))
        
        (let
            ((validated-deposit {
                amount: amount,
                recipient: recipient,
                processed: false,
                confirmations: u0,
                timestamp: stacks-block-height,
                btc-sender: btc-sender,
                validator-signatures: u0
            }))
            
            (map-set deposits
                {tx-hash: tx-hash}
                validated-deposit
            )
            
            (print {
                type: "deposit-initiated",
                tx-hash: tx-hash, 
                amount: amount,
                recipient: recipient,
                validator: tx-sender
            })
            
            (ok true)
        )
    )
)

;; Updates the confirmation count for a deposit
(define-public (update-confirmations
    (tx-hash (buff 32))
    (new-confirmations uint)
)
    (let (
        (deposit (unwrap! (map-get? deposits {tx-hash: tx-hash}) (err ERROR-INVALID-TX-HASH)))
        (is-validator (get-validator-status tx-sender))
    )
        (asserts! (not (var-get bridge-paused)) (err ERROR-BRIDGE-PAUSED))
        (asserts! is-validator (err ERROR-NOT-AUTHORIZED))
        (asserts! (> new-confirmations (get confirmations deposit)) (err ERROR-INVALID-BRIDGE-STATUS))
        
        (map-set deposits
            {tx-hash: tx-hash}
            (merge deposit {confirmations: new-confirmations})
        )
        
        (ok true)
    )
)

;; Confirms a deposit into the bridge. Validators must call this function.
(define-public (confirm-deposit 
    (tx-hash (buff 32))
    (signature (buff 65))
)
    (let (
        (deposit (unwrap! (map-get? deposits {tx-hash: tx-hash}) (err ERROR-INVALID-BRIDGE-STATUS)))
        (is-validator (get-validator-status tx-sender))
    )
        (asserts! (not (var-get bridge-paused)) (err ERROR-BRIDGE-PAUSED))
        (asserts! is-validator (err ERROR-NOT-AUTHORIZED))
        (asserts! (is-valid-tx-hash tx-hash) (err ERROR-INVALID-TX-HASH))
        (asserts! (is-valid-signature signature) (err ERROR-INVALID-SIGNATURE-FORMAT))
        (asserts! (not (get processed deposit)) (err ERROR-ALREADY-PROCESSED))
        (asserts! (>= (get confirmations deposit) REQUIRED-CONFIRMATIONS) (err ERROR-INVALID-BRIDGE-STATUS))
        
        (asserts! 
            (is-none (map-get? validator-signatures {tx-hash: tx-hash, validator: tx-sender}))
            (err ERROR-DUPLICATE-SIGNATURE)
        )
        
        (let
            ((validated-signature {
                signature: signature,
                timestamp: stacks-block-height
            })
             (updated-sig-count (+ (get validator-signatures deposit) u1)))
            
            ;; Add the validator signature record
            (map-set validator-signatures
                {tx-hash: tx-hash, validator: tx-sender}
                validated-signature
            )
            
            ;; Update the deposit record with increased signature count
            (map-set deposits
                {tx-hash: tx-hash}
                (merge deposit {validator-signatures: updated-sig-count})
            )
            
            ;; If we've reached the threshold, process the deposit
            (if (>= updated-sig-count VALIDATOR-THRESHOLD)
                (process-validated-deposit tx-hash)
                (ok true)
            )
        )
    )
)

;; Private function to process a fully validated deposit
(define-private (process-validated-deposit (tx-hash (buff 32)))
    (let (
        (deposit (unwrap! (map-get? deposits {tx-hash: tx-hash}) (err ERROR-INVALID-TX-HASH)))
    )
        (asserts! (not (get processed deposit)) (err ERROR-ALREADY-PROCESSED))
        (asserts! (>= (get validator-signatures deposit) VALIDATOR-THRESHOLD) 
                 (err ERROR-VALIDATOR-THRESHOLD-NOT-MET))
        
        ;; Mark as processed
        (map-set deposits
            {tx-hash: tx-hash}
            (merge deposit {processed: true})
        )
        
        ;; Update the recipient's balance
        (map-set bridge-balances
            (get recipient deposit)
            (+ (default-to u0 (map-get? bridge-balances (get recipient deposit))) 
               (get amount deposit))
        )
        
        ;; Update total bridged amount
        (var-set total-bridged-amount 
            (+ (var-get total-bridged-amount) (get amount deposit))
        )
        
        (print {
            type: "deposit-processed",
            tx-hash: tx-hash,
            amount: (get amount deposit),
            recipient: (get recipient deposit),
            signatures: (get validator-signatures deposit)
        })
        
        (ok true)
    )
)