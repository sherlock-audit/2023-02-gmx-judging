IllIllI

high

# Pool value calculation uses wrong portion of the borrowing fees

## Summary

The calculation of a pool's value incorrectly includes the fee receiver portion of the borrowing fees, rather than the pool's portion


## Vulnerability Detail

Borrowing fees consist of two parts - the amount that the pool gets, and the amount the fee receiver address gets. Multiplying the total borrowing fees by the factor results in the amount the fee receiver is supposed to get, not the amount the pool is supposed to get. The code incorrectly includes the fee receiver amount rather than the pool amount, when calculating the pool's value.


## Impact

The `getPoolValue()` function is used to determine how many shares [to mint](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol#L317-L323) for a deposit of collateral tokens, and how many collateral tokens to get back during [withdrawal](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/withdrawal/WithdrawalUtils.sol#L446-L462), and for [viewing](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/market/MarketUtils.sol#L186-L205) the value of market tokens.

This means the accounting of value is wrong, and therefore some LPs will get more for their tokens than they should, and some less, and these will be principal losses.


## Code Snippet

```solidity
// File: gmx-synthetics/contracts/market/MarketUtils.sol : MarketUtils.getPoolValue()   #1

334            cache.value = cache.longTokenUsd + cache.shortTokenUsd;
335    
336            cache.totalBorrowingFees = getTotalBorrowingFees(dataStore, market.marketToken, market.longToken, market.shortToken, true);
337            cache.totalBorrowingFees += getTotalBorrowingFees(dataStore, market.marketToken, market.longToken, market.shortToken, false);
338    
339            cache.borrowingFeeReceiverFactor = dataStore.getUint(Keys.BORROWING_FEE_RECEIVER_FACTOR);
340 @>         cache.value += Precision.applyFactor(cache.totalBorrowingFees, cache.borrowingFeeReceiverFactor);
341    
342            cache.impactPoolAmount = getPositionImpactPoolAmount(dataStore, market.marketToken);
343            cache.value += cache.impactPoolAmount * indexTokenPrice.pickPrice(maximize);
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/market/MarketUtils.sol#L329-L349


## Tool used

Manual Review


## Recommendation

Use the pool's portion of the borrowing fees:
```diff
diff --git a/gmx-synthetics/contracts/market/MarketUtils.sol b/gmx-synthetics/contracts/market/MarketUtils.sol
index 7624b69..bd006bf 100644
--- a/gmx-synthetics/contracts/market/MarketUtils.sol
+++ b/gmx-synthetics/contracts/market/MarketUtils.sol
@@ -337,7 +337,7 @@ library MarketUtils {
         cache.totalBorrowingFees += getTotalBorrowingFees(dataStore, market.marketToken, market.longToken, market.shortToken, false);
 
         cache.borrowingFeeReceiverFactor = dataStore.getUint(Keys.BORROWING_FEE_RECEIVER_FACTOR);
-        cache.value += Precision.applyFactor(cache.totalBorrowingFees, cache.borrowingFeeReceiverFactor);
+        cache.value += cache.totalBorrowingFees - Precision.applyFactor(cache.totalBorrowingFees, cache.borrowingFeeReceiverFactor);
 
         cache.impactPoolAmount = getPositionImpactPoolAmount(dataStore, market.marketToken);
         cache.value += cache.impactPoolAmount * indexTokenPrice.pickPrice(maximize);
```

