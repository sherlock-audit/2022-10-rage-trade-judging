GimelSec

high

# If a user approves junior vault tokens to WithdrawPeriphery, anyone can withdraw/redeem his/her token

## Summary

If users want to withdraw/redeem tokens by WithdrawPeriphery, they should approve token approval to WithdrawPeriphery, then call `withdrawToken()` or `redeemToken()`.
But if users approve `dnGmxJuniorVault` to WithdrawPeriphery, anyone can withdraw/redeem his/her token.

## Vulnerability Detail

Users should approve `dnGmxJuniorVault` before calling `withdrawToken()` or `redeemToken()`:

```solidity
    function withdrawToken(
        address from,
        address token,
        address receiver,
        uint256 sGlpAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.withdraw(sGlpAmount, address(this), from);
...

    function redeemToken(
        address from,
        address token,
        address receiver,
        uint256 sharesAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.redeem(sharesAmount, address(this), from);
...
```

For better user experience, we always use `approve(WithdrawPeriphery, type(uint256).max)`. It means that if Alice approves the max amount, anyone can withdraw/redeem her tokens anytime.
Another scenario is that if Alice approves 30 amounts, she wants to call `withdrawToken` to withdraw 30 tokens. But in this case Alice should send two transactions separately, then an attacker can frontrun `withdrawToken` transaction and withdraw Alice’s token.

## Impact

Attackers can frontrun withdraw/redeem transactions and steal tokens. And some UI always approves max amount, which means that anyone can withdraw users tokens.

## Code Snippet

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/periphery/WithdrawPeriphery.sol#L119-L120
https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/periphery/WithdrawPeriphery.sol#L139-L140

## Tool used

Manual Review

## Recommendation

Replace `from` parameter by `msg.sender`.

```solidity
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.withdraw(sGlpAmount, address(this), msg.sender);

        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.redeem(sharesAmount, address(this), msg.sender);
```
