float-audits

high

# Incorrect token address set in `Oracle.sol`

## Summary

Token address does not update with each token in the `for` loop in `clearAllPrices()` function in `Oracle.sol`

## Vulnerability Detail

Function `clearAllPrices()` is expected to clear all the prices (primary, secondary and custom) for all tokens iterated over, however address token is always set to `tokensWithPrices.at(0)` in each iteration.

LoC: https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L288

## Impact

This prevents some tokens from having their previous prices cleared, and this will cause revert in `setPrices` function as the previous prices are not wiped out.
This prevents any deposit and more importantly redeems from taking place for any user for all tokens affected.

## Code Snippet
```solidity
  // @dev clear all prices
  function clearAllPrices() external onlyController {
      uint256 length = tokensWithPrices.length();
      for (uint256 i = 0; i < length; i++) {
          address token = tokensWithPrices.at(0);
          delete primaryPrices[token];
          delete secondaryPrices[token];
          delete customPrices[token];
          tokensWithPrices.remove(token);
      }
  }
```

## Tool used

Manual Review

## Recommendation

replace assignment with `address token = tokensWithPrices.at(i);`


