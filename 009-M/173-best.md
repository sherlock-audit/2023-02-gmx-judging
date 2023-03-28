IllIllI

medium

# Gas spikes after outages may prevent order execution

## Summary

Users are required to specify execution fee at order creation. This fee is to reimburse the keeper for executing their order, and is based on a formula that includes the `tx.price` of the keeper when it executes the order.


## Vulnerability Detail

If the user submits an order to exit the position, and specifies a very generous execution fee, there may be an outage in the keeper or oracle network that delays the execution of the order. When the outage is resolved, the transaction gas fees may spike because of all of the queued orders that were waiting for the network to come back (similar to a long-on storm), and or due to other protocols trying to service their own liquidations.

In such a scenario, the user's oracle price is protected for a certain amount of time, but after that window passes, the order won't be executable. The issue is that there is no way for the user to update the execution fee so that it still gets executed during the gas spike, without altering their execution price.


## Impact

It's entirely possible that the provided execution fee would generally be described as excessive, at the time of order creation, but due to the outage it became insufficient. During the time window where the order isn't executed, the user's position may change from a profit, to a loss, or even become liquidated.


## Code Snippet

Updating the execution fee always touches the order, which changes the update timestamp, which is used to decide which oracle prices are valid:
```solidity
// File: gmx-synthetics/contracts/exchange/OrderHandler.sol : OrderHandler.   #1

88             // allow topping up of executionFee as partially filled or frozen orders
89             // will have their executionFee reduced
90             address wnt = TokenUtils.wnt(dataStore);
91             uint256 receivedWnt = orderVault.recordTransferIn(wnt);
92 @>          order.setExecutionFee(order.executionFee() + receivedWnt);
93     
94             uint256 estimatedGasLimit = GasUtils.estimateExecuteOrderGasLimit(dataStore, order);
95             GasUtils.validateExecutionFee(dataStore, estimatedGasLimit, order.executionFee());
96     
97 @>          order.touch();
98             OrderStoreUtils.set(dataStore, key, order);
99     
100            OrderEventUtils.emitOrderUpdated(eventEmitter, key, sizeDeltaUsd, triggerPrice, acceptablePrice);
101:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/OrderHandler.sol#L68-L101

## Tool used

Manual Review


## Recommendation

Allow the user to update the execution fee without changing the order timestamp if the `tx.gasprice` of the update transaction is above some threshold/execution fee factor 

