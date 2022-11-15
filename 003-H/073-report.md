keccak123

high

# Incorrect Uniswap Paths

## Summary

In DnGmxJuniorVaultManager, the functions `USDC_TO_WBTC` and `WBTC_TO_USDC` are identical. The return value in `USDC_TO_WBTC` is wrong. The same problem is found with `WETH_TO_USDC` and `USDC_TO_WETH`.

## Vulnerability Detail

In DnGmxJuniorVaultManager, [line 1456](https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/libraries/DnGmxJuniorVaultManager.sol#L1456) indicates that the SwapRouter used is the Uniswap V3 SwapRouter. The [Uniswap V3 docs explain](https://docs.uniswap.org/protocol/guides/swaps/multihop-swaps#exact-input-multi-hop-swaps) that a multihop swap is built by ordering the tokens in the order that the swap should happen. When examining the `USDC_TO_WBTC` and `WBTC_TO_USDC` functions in DnGmxJuniorVaultManager, the swaps are ordered the same way. The `USDC_TO_WBTC` will therefore result in a WBTC to USDC swap. The same is found with `USDC_TO_WETH`, where WETH will be swapped to USDC instead of vice versa. The end result is that the contract will normally revert when `USDC_TO_WBTC` or `USDC_TO_WETH` is called and users will be unable to use Rage Finance for conversions in that direction.

## Impact

The `USDC_TO_WBTC` and `USDC_TO_WETH` function are implemented incorrectly. The swaps will not happen in the intended direction.

## Code Snippet
Incorrect `USDC_TO_WETH` implementation
https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/libraries/DnGmxJuniorVaultManager.sol#L1529

Incorrect `USDC_TO_WBTC` implementation
https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/libraries/DnGmxJuniorVaultManager.sol#L1536

## Tool used

Manual Review

## Recommendation

The functions should be implemented like this
```solidity
function USDC_TO_WETH(State storage state) internal view returns (bytes memory) {
    return abi.encodePacked(state.usdc, uint24(500), state.weth);
}

function USDC_TO_WBTC(State storage state) internal view returns (bytes memory) {
    return abi.encodePacked(state.usdc, uint24(500), state.weth, uint24(3000), state.wbtc);
}
```