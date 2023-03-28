IllIllI

high

# Collateral cannot be claimed because there is no mechanism for the config keeper to change the claimable factor

## Summary

Collateral given back to a user due to capped price impacts cannot be claimed because there is no mechanism for the config keeper to set the claimable factor

## Vulnerability Detail

The code that claims the collateral for the user only gives back a percentage of the collateral based on a "factor", but there is no function to change the factor from the default of zero.


## Impact

The user will never be able to claim any of this collateral back, which is a principal loss.

Needing to let users claim their collateral is mainly for when large liquidations cause there to be large impact amounts. While this is not an everyday occurrence, large price gaps and liquidations are a relatively common occurrence in crypto, happening every couple of months, so needing this functionality will be required in the near future. Fixing the issue would require winding down all open positions and requiring LPs to withdraw their collateral, and re-deploying with new code.


## Code Snippet

```solidity
// File: gmx-synthetics/contracts/market/MarketUtils.sol : MarketUtils.claimCollateral()   #1

627            uint256 claimableAmount = dataStore.getUint(Keys.claimableCollateralAmountKey(market, token, timeKey, account));
628 @>         uint256 claimableFactor = dataStore.getUint(Keys.claimableCollateralFactorKey(market, token, timeKey, account));
629            uint256 claimedAmount = dataStore.getUint(Keys.claimedCollateralAmountKey(market, token, timeKey, account));
630    
631 @>         uint256 adjustedClaimableAmount = Precision.applyFactor(claimableAmount, claimableFactor);
632 @>         if (adjustedClaimableAmount >= claimedAmount) {
633                revert CollateralAlreadyClaimed(adjustedClaimableAmount, claimedAmount);
634:           }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/market/MarketUtils.sol#L622-L644


## Tool used

Manual Review


## Recommendation

```diff
diff --git a/gmx-synthetics/contracts/config/Config.sol b/gmx-synthetics/contracts/config/Config.sol
index 9bb382c..7696eb6 100644
--- a/gmx-synthetics/contracts/config/Config.sol
+++ b/gmx-synthetics/contracts/config/Config.sol
@@ -232,6 +232,8 @@ contract Config is ReentrancyGuard, RoleModule, BasicMulticall {
         allowedBaseKeys[Keys.MIN_COLLATERAL_FACTOR_FOR_OPEN_INTEREST_MULTIPLIER] = true;
         allowedBaseKeys[Keys.MIN_COLLATERAL_USD] = true;
 
+        allowedBaseKeys[Keys.CLAIMABLE_COLLATERAL_FACTOR] = true;
+
         allowedBaseKeys[Keys.VIRTUAL_TOKEN_ID] = true;
         allowedBaseKeys[Keys.VIRTUAL_MARKET_ID] = true;
         allowedBaseKeys[Keys.VIRTUAL_INVENTORY_FOR_SWAPS] = true;
```

