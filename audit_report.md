

# Comprehensive Security Audit Report: SafestVault & SafeLock Contracts

**Auditor:** Jimmy Lin <br>
**Date:** 2025-08-19 <br>
**Scope:** SafestVault.sol, SafeLock.sol <br>
**Total Bugs Found:** 36

**Brief Summary:** This audit identifies critical vulnerabilities in both contracts, including unauthorized fund access, broken reward calculations, oracle manipulation risks, and fundamental architectural flaws. The `SafeLock` contract has severe access control issues allowing complete fund drainage and timestamp manipulation vulnerabilities. `SafestVault` has significant oracle manipulation risks, accounting inconsistencies, and denial-of-service vectors. **Both contracts require a substantial redesign before any production deployment.**

---

## SEVERITY DEFINITIONS

### Critical
- **Direct loss of funds** with high probability.
- **Complete contract compromise** allowing unauthorized access to all assets.
- **Immediate exploitation** possible with minimal effort.
- **Examples:** Unauthorized fund drainage, broken access controls, direct theft vectors.

### High
- **Significant financial loss** or **contract malfunction**.
- **User funds at risk** under specific conditions.
- **Core functionality broken** affecting primary use cases.
- **Examples:** Failed withdrawals, price manipulation, accounting errors, reentrancy attacks.

### Medium
- **Limited financial impact** or **degraded functionality**.
- **User experience issues** that don't directly risk funds.
- **Edge case vulnerabilities** requiring specific conditions.
- **Examples:** Gas inefficiencies, parameter mismatches, access control gaps.

### Low
- **Minimal impact** on functionality or security.
- **Future risks** or **theoretical vulnerabilities**.
- **Code quality issues** with no immediate exploitation risk.
- **Examples:** Overflow risks in the distant future, minor rounding errors.

---

## CRITICAL SEVERITY BUGS (6 Total)

### Bug 1: Unauthorized Fund Drainage (SafeLock)
**Line:** 183-187
**Code Snippet:**
```solidity
function collectFlashloanFee(uint256 amount) external {
    require(amount <= address(this).balance, "Insufficient balance");
    payable(msg.sender).transfer(amount);
    require(totalRewards <= address(this).balance, "Insufficient balance");
}
```
**Impact:** The function lacks any access control, allowing any external caller to drain the entire ETH balance of the contract, including user rewards and flash loan fees.
**Exploitation:** An attacker calls `collectFlashloanFee(address(this).balance)` to steal all ETH held by the contract.

### Bug 2: Broken Reward Calculation System (SafeLock)
**Line:** 144-149
**Code Snippet:**
```solidity
function calculateRewards(address userAddress) public view returns (uint256) {
    // ...
    return ((MAX_REWARD * user.duration) / MAX_LOCK_DURATION);
}
```
**Impact:** The reward calculation is fundamentally flawed. It grants a fixed reward based only on lock duration, ignoring the user's staked amount. This allows users to claim disproportionately large rewards with minimal capital.
**Exploitation:** A user deposits the smallest possible share amount for the maximum duration to claim a full 1 ETH reward, effectively draining the reward pool.

### Bug 3: Balance Underflow Vulnerability (SafestVault)
**Line:** 275-276
**Code Snippet:**
```solidity
_userAccounts[owner].balances[token] -= (swapOn ? amountInUnderlying : amountInOriginalToken);
```
**Impact:** The withdrawal logic subtracts from a user's balance without first checking if the balance is sufficient. This can lead to an arithmetic underflow, causing the transaction to revert and potentially locking user funds.
**Exploitation:** If internal accounting becomes inconsistent, a user's withdrawal could fail permanently due to this missing check.

### Bug 4: Flash Loan Reentrancy Risk (SafeLock)
**Line:** 168
**Code Snippet:**
```solidity
IFlashLoanReceiver(msg.sender).receiveFlashLoan(amount, data);
```**Impact:** The contract transfers shares to a user and then calls an external contract (`receiveFlashLoan`) before verifying repayment. This violates the checks-effects-interactions pattern and exposes the contract to reentrancy attacks.
**Exploitation:** A malicious borrower's contract could re-enter other `SafeLock` functions (e.g., `withdraw`) during the flash loan callback to manipulate state before the repayment check occurs.

### Bug 5: Oracle Price Manipulation via Stale Price (SafestVault)
**Line:** 383
**Code Snippet:**
```solidity
(, int256 price, , , ) = priceOracle.latestRoundData();
```
**Impact:** The contract fetches the latest price from a Chainlink oracle but fails to check the `updatedAt` timestamp. This allows an attacker to use stale, incorrect prices during periods of oracle downtime or network congestion.
**Exploitation:** If the oracle price is stale and lower than the real market price, an attacker can deposit tokens at an inflated value, minting excess shares and stealing value from other LPs.

### Bug 6: Reward Calculation Ignores Available ETH (SafeLock)
**Line:** 148
**Code Snippet:**
```solidity
return ((MAX_REWARD * user.duration) / MAX_LOCK_DURATION);
```
**Impact:** The `calculateRewards` function promises rewards without checking if the contract actually holds enough ETH to pay them. This can lead to a situation where total promised rewards exceed the contract's balance, causing later withdrawals to fail.
**Exploitation:** Early withdrawers can drain the reward pool, leaving nothing for users who locked for longer durations, despite the contract showing they are owed a reward.

---

## HIGH SEVERITY BUGS (10 Total)

### Bug 7: Unsafe Timestamp Casting and Overflow (SafeLock)
**Line:** 76
**Code Snippet:**
```solidity
uint32 expiry = uint32(block.timestamp) + lockDuration;
```
**Impact:** The code unsafely casts `block.timestamp` (a `uint256`) to `uint32` and adds a `uint32 lockDuration`. This sum can easily overflow the `uint32` type, allowing an attacker to set an expiry date in the past and bypass the lock-up period.
**Exploitation:** An attacker provides a crafted `lockDuration` that causes the `expiry` calculation to wrap around, making the lock expire immediately. They can then withdraw their funds and rewards instantly.

### Bug 8: Fundamental Share Accounting Desynchronization (SafeLock)
**Impact:** **(ENHANCED)** `SafeLock` only tracks balances via its internal `deposit` and `withdraw` functions. It is completely unaware of standard ERC20 `transfer()` operations on the VAULT token. This is a fundamental architectural flaw where the contract's internal accounting can become completely desynchronized from the actual token ownership.
**Exploitation:** A user can lock shares, then transfer those shares to another address. The contract will still believe the original user has them locked, leading to incorrect reward calculations and broken withdrawal logic.

### Bug 9: ETH Transfer Failures via `transfer()` (SafestVault & SafeLock)
**Line:** `SafestVault:336`, `SafeLock:114, 185`
**Impact:** Both contracts use `payable(msg.sender).transfer(amount)`, which forwards a fixed gas stipend of 2300. This is insufficient for recipients that are smart contracts with complex fallback functions, causing withdrawals to fail.
**Exploitation:** Any user with a smart contract wallet (e.g., a multisig or a contract-based account) will be unable to withdraw ETH.

### Bug 10: Incorrect Uniswap Price Calculation (SafestVault)
**Line:** 369-370
**Code Snippet:**
```solidity
uint256 price = (uint256(sqrtPriceX96) * uint256(sqrtPriceX96)) / (2 ** 192);
estimatedAmountOut = (amountIn * (price)) / (1e18);
```
**Impact:** This formula for calculating the swap amount from a Uniswap V3 pool price incorrectly assumes both tokens have 18 decimals. If one token has a different number of decimals (e.g., USDC with 6), the calculation will be wrong, causing significant value loss during swaps.
**Exploitation:** A user depositing a non-18-decimal token will receive a completely incorrect amount of the underlying token, leading to direct financial loss.

### Bug 11: First Depositor Attack / Value Loss (SafestVault)
**Line:** 313
**Code Snippet:**
```solidity
shares = amount - MINIMUM_SHARES;
```
**Impact:** The first depositor's minted shares are calculated by subtracting `MINIMUM_SHARES` (1000) from their deposit amount. These 1000 shares are never minted to anyone and represent a permanent loss of value from the system, equivalent to the first 1000 wei of underlying tokens.
**Exploitation:** The first depositor is unfairly penalized. An attacker could also front-run the first legitimate depositor with a tiny deposit to ensure the legitimate user suffers this loss.

### Bug 12: Fee-on-Transfer Token Vulnerability (SafestVault)
**Line:** 216, 220
**Impact:** The contract calculates shares based on the `amount` parameter of a deposit but does not verify the actual balance received. If a fee-on-transfer token is used, the contract will receive less than `amount` but mint shares as if it received the full amount.
**Exploitation:** An attacker deposits a fee-on-transfer token, inflating their share of the pool and effectively stealing value from other liquidity providers.

### Bug 13: Auto-Swap Vulnerable to Sandwich Attacks (SafestVault)
**Line:** 280-304
**Impact:** The `_swapTokenForUnderlying` function performs swaps with a hardcoded, wide slippage tolerance (5%) and does not allow the user to specify a minimum amount out. This makes every deposit vulnerable to sandwich attacks.
**Exploitation:** A MEV bot can front-run a user's deposit, manipulate the Uniswap pool price, let the user's swap execute at a poor rate, and then back-run it to capture the profit, all at the user's expense.

### Bug 14: Withdrawal Accounting Logic Flaw (SafestVault)
**Line:** 245-246
**Code Snippet:**
```solidity
amountInUnderlying = (shares * (_totalAssets)) / totalSupply();
_totalAssets -= amountInUnderlying;
```
**Impact:** The calculation for `amountInUnderlying` uses the state of `_totalAssets` *before* it is reduced. In scenarios with multiple simultaneous withdrawals, this can lead to rounding errors and accounting inconsistencies over time.
**Exploitation:** This is not directly exploitable for theft but represents a flaw that can cause slow value drain or accounting drift within the vault.

### Bug 15: Flash Loan Repayment Logic Flaw (SafeLock)
**Line:** 172
**Code Snippet:**
```solidity
require(sharesToken.balanceOf(address(this)) >= totalLockedShares, "Flash loan not repaid");
```
**Impact:** The repayment check only ensures the contract's final balance is at least `totalLockedShares`. It does not confirm that the specific `amount` borrowed was returned.
**Exploitation:** If the contract holds extra, unlocked shares (e.g., from a direct transfer), a borrower could repay less than the borrowed amount, and the check would still pass, resulting in theft of the difference.

### Bug 16: Reentrancy Risk in `receive()` Fallback (SafestVault)
**Line:** 76
**Code Snippet:**
```solidity
deposit(address(0), msg.value, msg.sender);
```
**Impact:** The `receive()` function for accepting raw ETH calls the public `deposit` function, which is not protected by a reentrancy guard. This allows a malicious contract to re-enter the vault during an ETH deposit.
**Exploitation:** A contract could call `deposit()` again from its fallback function during an ETH transfer, potentially manipulating state or minting shares incorrectly.

---

## MEDIUM SEVERITY BUGS (15 Total)

### Bug 17: Unauthorized Share Burning with State Reset (SafestVault)
**Impact:** **(ENHANCED)** The `_burnShares` function is `public` instead of `internal`, allowing anyone to burn shares from any user. Crucially, if a user's balance is burned to zero, their `_userAccounts` entry is deleted, resetting their `swapOn` preference without their consent.
**Exploitation:** An attacker can call `_burnShares(victim.balanceOf(), victim)` to not only destroy the victim's funds but also reset their account state, causing their next deposit to behave unexpectedly.

### Bug 18: `alwaysUnderlying` Griefing Attack (SafestVault)
**Line:** 87-89
**Impact:** The `alwaysUnderlying()` function requires the caller to have a zero share balance. This allows an attacker to perpetually prevent a user from calling this function successfully.
**Exploitation:** An attacker monitors the mempool for `alwaysUnderlying()` calls and front-runs the transaction by sending 1 wei of shares to the victim. The victim's transaction will then fail the `balanceOf(msg.sender) == 0` check.

### Bug 19: Flash Loan Fee Inflates Share Value Unfairly (SafestVault)
**Line:** 161
**Impact:** Flash loan fees are added directly to `_totalAssets` without minting new shares. This increases the value of all existing shares, unfairly distributing the fee revenue to current LPs at the expense of the flash loan facilitator (the contract owner/DAO).
**Exploitation:** This is less of an attack and more of a design flaw that misallocates protocol revenue, benefiting existing LPs instead of a designated treasury.

### Bug 20: Irreversible `swapOn` Flag (SafestVault)
**Line:** 88
**Impact:** Once a user sets their `swapOn` flag to true, there is no function to set it back to false. This is a permanent, irreversible state change for the user's account.
**Exploitation:** A user who accidentally enables swapping cannot disable it, forcing all future deposits to be swapped even if they change their strategy.

### Bug 21: Excessive Hardcoded Slippage (SafestVault)
**Line:** 286
**Impact:** The contract hardcodes a 5% slippage tolerance (`* (95)) / (100)`), which is extremely high for most stable trading pairs and exposes users to significant value loss on every auto-swap deposit.
**Exploitation:** Normal market volatility, or manipulation via sandwich attacks (see Bug #13), can cause users to lose up to 5% of their deposit value.

### Bug 22: Short Swap Deadline (SafestVault)
**Line:** 297
**Impact:** The Uniswap swap deadline is hardcoded to `block.timestamp + 15`, a mere 15 seconds. During times of high network congestion, this is often not enough time for a transaction to be mined, causing it to fail.
**Exploitation:** Users' deposit transactions will frequently revert during busy network periods, costing them gas and providing a poor user experience.

### Bug 23: Silent Failure on Emergency Withdraw (SafestVault)
**Line:** 182
**Impact:** The `emergencyWithdraw` function uses `token.transfer()` but does not check the boolean return value. Some ERC20 tokens (like USDT) do not revert on failure but instead return `false`, causing the transfer to fail silently.
**Exploitation:** The owner might believe they have successfully withdrawn stuck tokens when, in fact, the transaction had no effect, potentially leading to a loss of funds if the issue isn't noticed.

### Bug 24: `depositWithPermit` Parameter Mismatch (SafestVault)
**Line:** 118, 126
**Impact:** The function calls `IERC20Permit(token).permit(msg.sender, ...)` but then calls `_internalDeposit(..., owner, ...)` using a separate `owner` parameter. This is inconsistent; `permit` always approves for `msg.sender`, so `owner` should also be `msg.sender`.
**Exploitation:** This will cause any `depositWithPermit` call where `owner` is not `msg.sender` to fail, as the permit signature will be invalid for the intended depositor.

### Bug 25: Gas Inefficient State Updates (SafeLock)
**Line:** 75, 100
**Impact:** The `deposit` and `withdraw` functions load the entire `User` struct into memory (`User memory user = ...`), modify it, and then write the entire struct back to storage. This is less gas-efficient than directly updating storage variables (`User storage user = ...`).
**Exploitation:** Users will pay higher gas fees than necessary for core contract interactions.

### Bug 26: Flash Loan Interface Check Missing (SafeLock)
**Line:** 168
**Impact:** The contract transfers shares to the `msg.sender` before verifying that it correctly implements the `IFlashLoanReceiver` interface.
**Exploitation:** If shares are sent to a contract that does not have a `receiveFlashLoan` function, the external call will fail, but the shares will have already been transferred and may become stuck.

### Bug 27: Withdrawal Parameter Order Error (SafestVault)
**Line:** 134
**Impact:** The public `withdraw` function's parameters are `(token, shares, receiver)`, but the internal `_internalWithdraw` function expects `(token, shares, owner, receiver)`. The public function calls it as `_internalWithdraw(token, shares, receiver, msg.sender)`, effectively passing `receiver` as the `owner` and `msg.sender` as the `receiver`.
**Exploitation:** This will cause withdrawals to fail security checks (`require(balanceOf(owner) >= shares)`) or send funds to the wrong address (`msg.sender` instead of the intended `receiver`).

### Bug 28: Ineffective Post-Transfer Balance Check (SafeLock)
**Line:** 186
**Impact:** In `collectFlashloanFee`, the check `require(totalRewards <= address(this).balance)` happens *after* the ETH has already been transferred out. This makes the check useless, as it only verifies the state after the potentially damaging transfer has occurred.
**Exploitation:** The check provides a false sense of security and does nothing to prevent the fund drainage described in Bug #1.

### Bug 29: Single Lock Limitation Per User (SafeLock)
**Line:** 52
**Impact:** The `onlyOneActiveLock` modifier prevents users from having more than one lock at a time. This severely limits user flexibility, as they cannot create multiple locks with different amounts or durations.
**Exploitation:** This is a design limitation, not a direct exploit, but it harms the user experience and protocol utility.

### Bug 30: Uniswap Pool Existence Check is Insufficient (SafestVault)
**Line:** 365
**Impact:** The code checks that a Uniswap pool exists (`pool != address(0)`) but does not check if the pool has any liquidity.
**Exploitation:** A user could deposit a token for which a pool exists but is completely empty. The swap would revert, causing the deposit transaction to fail and wasting gas.

### Bug 31: Flash Loan Balance Check Timing Flaw (SafestVault)
**Line:** 146
**Impact:** Similar to the reentrancy risk in SafeLock's flash loan, this function transfers tokens to the borrower *before* making the external call. This gives the borrower control of execution while holding the contract's funds.
**Exploitation:** A malicious borrower could use the borrowed funds during the callback to manipulate other protocols that this vault might interact with in the future, before the repayment is verified.

---

## LOW SEVERITY BUGS (5 Total)

### Bug 32: Missing Zero Address Validation (SafestVault)
**Line:** 67, 173
**Impact:** The `constructor` and `setPriceFeed` function do not validate input addresses against `address(0)`. Setting critical addresses like the `underlyingToken` or a price feed to zero would permanently break core contract functionality.
**Exploitation:** An accidental misconfiguration during deployment or an owner error could render the contract inoperable.

### Bug 33: Missing Events for Critical State Changes (SafestVault)
**Line:** 87, 165, 173
**Impact:** Functions that change critical parameters (`alwaysUnderlying`, `setFlashLoanFee`, `setPriceFeed`) do not emit events. This makes it difficult for off-chain monitoring tools and users to track important configuration changes.
**Exploitation:** This is a best-practice violation that reduces transparency and makes the system harder to audit and monitor externally.

### Bug 34: Rounding Direction Bias in Share Calculation (SafestVault)
**Line:** 314
**Impact:** Solidity's integer division always truncates (rounds down). In the share calculation formula, this consistently favors the vault, causing a small amount of value to be retained by the contract over many transactions.
**Exploitation:** An attacker could perform many tiny deposit/withdraw cycles to intentionally abuse the rounding error, though the profit would likely be negligible.

### Bug 35: Flash Loan Fee Precision Loss (SafestVault)
**Line:** 353
**Impact:** The fee calculation `(amount * flashLoanFee) / 10000` uses integer division, which can round down to zero for small loan amounts.
**Exploitation:** An attacker could take many small flash loans for free if the `amount` is small enough that the calculated fee is less than 1 wei.

### Bug 36: Weak Emergency Withdraw Token Check (SafestVault)
**Line:** 181
**Impact:** The check `require(token != underlyingToken)` is weak. It only prevents withdrawal of the exact underlying token but would allow withdrawal of other valuable tokens like wrapped versions (e.g., WETH vs ETH) or stablecoins that might be accidentally sent to the contract.
**Exploitation:** While intended as a safety measure, this check could be bypassed if other forms of the underlying asset are held by the vault, though the `onlyOwner` modifier limits the direct risk.

---

## Final Summary & Recommendation

**Total Unique Bugs:** 36
- **Critical:** 6
- **High:** 10
- **Medium:** 15
- **Low:** 5

**Most Critical Issues:**
1.  **Unauthorized Fund Drainage (`SafeLock`):** Anyone can steal all ETH.
2.  **Broken Reward Logic (`SafeLock`):** Rewards are not tied to stake amount, allowing for easy draining.
3.  **Timestamp Overflow (`SafeLock`):** Lock-up periods can be bypassed entirely.
4.  **Fundamentally Broken Accounting (`SafeLock`):** The contract cannot track token ownership correctly.
5.  **Oracle Price Manipulation (`SafestVault`):** Stale prices can be used to steal value.

**Recommendation:**
These contracts, particularly **`SafeLock`**, suffer from fundamental architectural flaws that go beyond simple bugs. The issues identified are severe and systemic. Merely patching the individual vulnerabilities is insufficient.

**`SafeLock` requires a complete redesign and rewrite.** Its accounting model is broken, its reward logic is exploitable, and it lacks basic access controls.

**`SafestVault` needs significant refactoring** to address oracle safety, reentrancy risks, accounting precision, and user-facing issues like slippage and transaction deadlines.

**It is strongly recommended that these contracts NOT be deployed to a production environment in their current state.**