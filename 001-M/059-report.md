ctf_sec

medium

# User can call executeBatchDeposit any time to unpause the vault and DOS the vault by calling deposit

## Summary

User can call executeBatchDeposit any time to unpause the vault and DOS the vault.

## Vulnerability Detail

The keeper can pause or unpause the contract DnGmxBatchingManager.sol

```solidity
/// @notice pauses deposits (to prevent DOS due to GMX 15 min cooldown)
function pauseDeposit() external onlyKeeper {
    _pause();
}

/// @notice unpauses the deposit function
function unpauseDeposit() external onlyKeeper {
    _unpause();
}
```

> if one user deposits and we buy glp then and call _stakeGlp (rewardRouter.mintAndStakeGlp), then other user will have to wait 15 mins, so adversary can keep deposit very small amount every 15 mins and DOS it

> hence we convert deposit to shares only once or twice a day using executeBatch

(Quote from Protodev in Rage trade)

However, the user can simply call executeBatchDeposit multiple times to unpause the contract and continue to DOS the vault.

```solidity
/// @notice executes batch and deposits into appropriate vault with/without minting shares
function executeBatchDeposit() external {
  // If the deposit is paused then unpause on execute batch deposit
  if (paused()) _unpause();

  // Transfer vault glp directly, Needs to be called only for dnGmxJuniorVault
  if (dnGmxJuniorVaultGlpBalance > 0) {
      uint256 glpToTransfer = dnGmxJuniorVaultGlpBalance;
      dnGmxJuniorVaultGlpBalance = 0;
      sGlp.transfer(address(dnGmxJuniorVault), glpToTransfer);
      emit VaultDeposit(glpToTransfer);
  }

  _executeVaultUserBatchDeposit();
}
```

## Impact

User can extend to staking lock period 15 by 15 with small amount of shares. If the contract is paused, the user can simply unpause it.

## Code Snippet

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/vaults/DnGmxBatchingManager.sol#L157-L167

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/vaults/DnGmxBatchingManager.sol#L171-L195

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/vaults/DnGmxBatchingManager.sol#L238-L251

## Tool used

Manual Review

## Recommendation

We recommend the project add onlyKeeper modifier in executeBatchDeposit to not let anyone call for free.

```solidity
function executeBatchDeposit() external onlyKeeper
```
