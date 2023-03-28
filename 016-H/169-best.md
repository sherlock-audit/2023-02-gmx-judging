IllIllI

medium

# Primary price is used for market orders, rather than secondary prices, as the comments indicate should be used

## Summary

Market orders use the primary (oldest) price for market orders, rather than the secondary (fresher) price, even though the comments say the opposite should be done


## Vulnerability Detail

The comments for the function state:
```solidity
    // for market orders, set the min and max values of the customPrice for the indexToken
    // to either secondaryPrice.min or secondaryPrice.max depending on whether the order
    // is an increase or decrease and whether it is for a long or short
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/order/BaseOrderUtils.sol#L184-L186

but the code uses the `primaryPrice`


## Impact

Users will get the wrong execution prices if there are price gaps, leading to false losses for the other side of the trade.


## Code Snippet

Uses the primary price, not the secondary price:
```solidity
// File: gmx-synthetics/contracts/order/BaseOrderUtils.sol : BaseOrderUtils.setExactOrderPrice()   #1

218            //     - short: use the smaller price
219            // decrease order:
220            //     - long: use the smaller price
221            //     - short: use the larger price
222            bool shouldUseMaxPrice = isIncrease ? isLong : !isLong;
223    
224            if (orderType == Order.OrderType.MarketIncrease ||
225                orderType == Order.OrderType.MarketDecrease ||
226                orderType == Order.OrderType.Liquidation) {
227    
228 @>             Price.Props memory price = oracle.getPrimaryPrice(indexToken);
229    
230                oracle.setCustomPrice(indexToken, Price.Props(
231                    price.pickPrice(shouldUseMaxPrice),
232                    price.pickPrice(shouldUseMaxPrice)
233                ));
234    
235                return;
236            }
237    
238:           if (orderType == Order.OrderType.LimitIncrease ||
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/order/BaseOrderUtils.sol#L218-L238

Consider a case where the user submits a market order with an acceptable price of 100, then the (primary,secondary) price comes in at (19,20) for the first block of the order then (20,9999) for the next. In this case the order will be executed during the second block, but the user will have gotten a price of 20, rather than the acceptable price of 100, so they can exit immediately for a profit.


## Tool used

Manual Review


## Recommendation

Use the secondary price so that they get the newer price or the acceptable price, whichever is smaller


