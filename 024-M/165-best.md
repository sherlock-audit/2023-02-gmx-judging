IllIllI

medium

# Orders with single-sided deposits that are auto-adjusted, always revert

## Summary

Deposits of only the long collateral token, when doing so results in an auto-adjustment of the order to minimize price impact, results in the order always reverting.


## Vulnerability Detail

The code that determines which order to subtract the two amounts in order to get a positive difference value, has the wrong equality condition, which means the difference operation reverts due to underflow.


## Impact

Single sided deposits as a feature are completely broken when the deposit doesn't solely push the swap impact towards a lower value.


## Code Snippet

Since the variables are `uint256`s, if `poolLongTokenAmount` is less than `poolShortTokenAmount`, subtracting the latter from the former will always revert. The else condition has the same issue:
```solidity
// File: gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol : ExecuteDepositUtils.getAdjustedLongAndShortTokenAmounts()   #1

392 @>         if (poolLongTokenAmount < poolShortTokenAmount) {
393 @>             uint256 diff = poolLongTokenAmount - poolShortTokenAmount;
394    
395                if (diff < poolLongTokenAmount) {
396                    adjustedLongTokenAmount = diff + (longTokenAmount - diff) / 2;
397                    adjustedShortTokenAmount = longTokenAmount - adjustedLongTokenAmount;
398                } else {
399                    adjustedLongTokenAmount = longTokenAmount;
400                }
401            } else {
402:@>             uint256 diff = poolShortTokenAmount - poolLongTokenAmount;
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol#L382-L402


## Tool used

Manual Review


## Recommendation

```diff
diff --git a/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol b/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol
index 03467e4..915c7fe 100644
--- a/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol
+++ b/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol
@@ -389,7 +389,7 @@ library ExecuteDepositUtils {
         uint256 adjustedLongTokenAmount;
         uint256 adjustedShortTokenAmount;
 
-        if (poolLongTokenAmount < poolShortTokenAmount) {
+        if (poolLongTokenAmount > poolShortTokenAmount) {
             uint256 diff = poolLongTokenAmount - poolShortTokenAmount;
 
             if (diff < poolLongTokenAmount) {
```
