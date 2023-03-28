IllIllI

high

# User-supplied slippage for decrease orders is ignored

## Summary

The user-supplied `minOutputAmount` order parameter for controlling slippage is ignored when a user decreases their position


## Vulnerability Detail

There are no checks that the amount out matches the user-supplied value during order creation, and in fact infinite slippage is allowed during the swap of PNL and collateral, ensuring there are opportunities for sandwiching.


## Impact

User's orders will have swap impacts applied to them during swaps, resulting in the user getting less than they asked for.


## Code Snippet

Infinite slippage is allowed during the swap from collateral tokens to the PNL token:
```solidity
// File: gmx-synthetics/contracts/position/DecreasePositionCollateralUtils.sol : DecreasePositionCollateralUtils.swapProfitToCollateralToken()   #1

425                try params.contracts.swapHandler.swap(
426                    SwapUtils.SwapParams(
427                        params.contracts.dataStore,
428                        params.contracts.eventEmitter,
429                        params.contracts.oracle,
430                        Bank(payable(params.market.marketToken)),
431                        pnlToken, // tokenIn
432                        profitAmount, // amountIn
433                        swapPathMarkets, // markets
434 @>                     0, // minOutputAmount
435                        params.market.marketToken, // receiver
436                        false // shouldUnwrapNativeToken
437                    )
438:               ) returns (address /* tokenOut */, uint256 swapOutputAmount) {
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/position/DecreasePositionCollateralUtils.sol#L425-L438

and during the swap of collateral tokens to PNL tokens:
```solidity
// File: gmx-synthetics/contracts/position/DecreasePositionCollateralUtils.sol : DecreasePositionCollateralUtils.swapWithdrawnCollateralToPnlToken()   #2

383                try params.contracts.swapHandler.swap(
384                    SwapUtils.SwapParams(
385                        params.contracts.dataStore,
386                        params.contracts.eventEmitter,
387                        params.contracts.oracle,
388                        Bank(payable(params.market.marketToken)),
389                        params.position.collateralToken(), // tokenIn
390                        values.output.outputAmount, // amountIn
391                        swapPathMarkets, // markets
392 @>                     0, // minOutputAmount
393                        params.market.marketToken, // receiver
394                        false // shouldUnwrapNativeToken
395                    )
396:               ) returns (address tokenOut, uint256 swapOutputAmount) {
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/position/DecreasePositionCollateralUtils.sol#L383-L396

And there are no checks in the calling layers that ensure that the final amount matches the [`minOutputAmount`](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/order/Order.sol#L92-L103) provided [`during order creation`](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/order/BaseOrderUtils.sol#L62-L70).


## Tool used

Manual Review


## Recommendation

`require()` that the final output amount is equal to the requested amount, after the position is [decreased](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/order/DecreaseOrderUtils.sol#L38-L47) but before funds are transferred.

