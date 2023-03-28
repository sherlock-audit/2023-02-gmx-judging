IllIllI

medium

# Single-sided deposits that are auto-adjusted may have their collateral value cut in half

## Summary

Deposits of only the long collateral token, when doing so results in an auto-adjustment of the order to minimize price impact, creating a larger adjusted short amount, does not properly track the new adjusted long amount.


## Vulnerability Detail

When such an adjustment is maid, the adjusted long amount is never updated, so it remains at the uninitialized value of zero.

## Impact

The long portion of the collateral will be zero. If the user submitted the order without specifying a minimum number of market tokens to receive, the amount they receive may be half of what it should have been. If they provide sane slippage amounts, the transaction will revert, and the feature will essentially be broken.


## Code Snippet

Rather than storing the result of the subtraction to the `adjustedLongTokenAmount` variable, the difference is subtracted from it, and the result is not stored:
```solidity
// File: gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol : ExecuteDepositUtils.getAdjustedLongAndShortTokenAmounts()   #1

389 @>         uint256 adjustedLongTokenAmount;
390            uint256 adjustedShortTokenAmount;
...
402                uint256 diff = poolShortTokenAmount - poolLongTokenAmount;
403    
404                if (diff < poolShortTokenAmount) {
405                    adjustedShortTokenAmount = diff + (longTokenAmount - diff) / 2;
406 @>                 adjustedLongTokenAmount - longTokenAmount - adjustedShortTokenAmount;
407                } else {
408                    adjustedLongTokenAmount = 0;
409                    adjustedShortTokenAmount = longTokenAmount;
410                }
411            }
412    
413            return (adjustedLongTokenAmount, adjustedShortTokenAmount);
414:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol#L389-L414

## Tool used

Manual Review


## Recommendation
```diff
diff --git a/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol b/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol
index 03467e4..1a96f47 100644
--- a/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol
+++ b/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol
@@ -403,7 +403,7 @@ library ExecuteDepositUtils {
 
             if (diff < poolShortTokenAmount) {
                 adjustedShortTokenAmount = diff + (longTokenAmount - diff) / 2;
-                adjustedLongTokenAmount - longTokenAmount - adjustedShortTokenAmount;
+                adjustedLongTokenAmount = longTokenAmount - adjustedShortTokenAmount;
             } else {
                 adjustedLongTokenAmount = 0;
                 adjustedShortTokenAmount = longTokenAmount;
```

