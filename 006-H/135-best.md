IllIllI

high

# Fee receiver is given twice the amount of borrow fees it's owed

## Summary

The fee receiver is given twice the amount of borrow fees it's owed, at the expense of the user's position


## Vulnerability Detail

The calculation of the total net cost of a position change double counts the portion of the fee related to how much the fee receiver gets of the fee of the borrowed amount.


## Impact

The fee receiver gets twice the amount owed, and the user is charged twice what they should be for that portion of their order


## Code Snippet
`borrowingFeeAmount` contains both the amount for the pool and the amount for the fee receiver. The `totalNetCostAmount` calculation includes the full `borrowingFeeAmount` even though the `feeReceiverAmount` is also included, and already contains the `borrowingFeeAmountForFeeReceiver`
```solidity
// File: gmx-synthetics/contracts/pricing/PositionPricingUtils.sol : PositionPricingUtils.getPositionFees()   #1

377 @>         fees.borrowingFeeAmount = MarketUtils.getBorrowingFees(dataStore, position) / collateralTokenPrice.min;
378    
379            uint256 borrowingFeeReceiverFactor = dataStore.getUint(Keys.BORROWING_FEE_RECEIVER_FACTOR);
380            uint256 borrowingFeeAmountForFeeReceiver = Precision.applyFactor(fees.borrowingFeeAmount, borrowingFeeReceiverFactor);
381    
382 @>         fees.feeAmountForPool = fees.positionFeeAmountForPool + fees.borrowingFeeAmount - borrowingFeeAmountForFeeReceiver;
383 @>         fees.feeReceiverAmount += borrowingFeeAmountForFeeReceiver;
384    
385            int256 latestLongTokenFundingAmountPerSize = MarketUtils.getFundingAmountPerSize(dataStore, position.market(), longToken, position.isLong());
386            int256 latestShortTokenFundingAmountPerSize = MarketUtils.getFundingAmountPerSize(dataStore, position.market(), shortToken, position.isLong());
387    
388            fees.funding = getFundingFees(
389                position,
390                longToken,
391                shortToken,
392                latestLongTokenFundingAmountPerSize,
393                latestShortTokenFundingAmountPerSize
394            );
395    
396 @>         fees.totalNetCostAmount = fees.referral.affiliateRewardAmount + fees.feeReceiverAmount + fees.positionFeeAmountForPool + fees.funding.fundingFeeAmount + fees.borrowingFeeAmount;
397            fees.totalNetCostUsd = fees.totalNetCostAmount * collateralTokenPrice.max;
398    
399            return fees;
400:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/pricing/PositionPricingUtils.sol#L377-L400

## Tool used

Manual Review


## Recommendation

```diff
diff --git a/gmx-synthetics/contracts/pricing/PositionPricingUtils.sol b/gmx-synthetics/contracts/pricing/PositionPricingUtils.sol
index c274e48..30bd6a8 100644
--- a/gmx-synthetics/contracts/pricing/PositionPricingUtils.sol
+++ b/gmx-synthetics/contracts/pricing/PositionPricingUtils.sol
@@ -393,7 +393,7 @@ library PositionPricingUtils {
             latestShortTokenFundingAmountPerSize
         );
 
-        fees.totalNetCostAmount = fees.referral.affiliateRewardAmount + fees.feeReceiverAmount + fees.positionFeeAmountForPool + fees.funding.fundingFeeAmount + fees.borrowingFeeAmount;
+        fees.totalNetCostAmount = fees.referral.affiliateRewardAmount + fees.feeReceiverAmount + fees.feeAmountForPool + fees.funding.fundingFeeAmount;
         fees.totalNetCostUsd = fees.totalNetCostAmount * collateralTokenPrice.max;
 
         return fees;
```

