caventa

medium

# There is no market enabled validation in Swap and CreateAdl activities

## Summary
There is no market enabled validation in Swap and CreateAdl activities.

## Vulnerability Detail
Controller may execute activities  for disabled market in Swaphandler and CreateAdlHandler

## Impact
Activities can still be performed on an disabled market

## Code Snippet
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/swap/SwapUtils.sol#L98-L149
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/swap/SwapUtils.sol#L158-L318
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/adl/AdlUtils.sol#L125-L173

## Tool used
Manual Review

## Recommendation
Add the similar following code

```solidity
Market.Props memory _market = MarketUtils.getEnabledMarket(dataStore, market);
```

to swap and createAdl
