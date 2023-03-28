kirk-baird

high

# `getAdjustedLongAndShortTokenAmounts()` Incorrectly Calculates Amounts

## Summary

The function `getAdjustedLongAndShortTokenAmounts()` attempts to balance the long and short pool amounts for a market which has the same long and short token. However, the calculations are incorrect and may result in an unbalanced pool or a reverted transaction.

## Vulnerability Detail

There are two equivalent bugs which occur depending on which pool is larger (long vs short). The bug occurs due to incorrect values being used in the if-statements.

The first issue is occurs on line 395 where the `diff` is compared to `poolLongTokenAmount`. This is the incorrect value, instead `longTokenAmount` should be used.

For the case where `diff < poolLongTokenAmount`
- if `longTokenAmount < diff` it will overflow on line 396
- if `longTokenAmount >= diff` this case behaves correctly
For the case where `diff >= poolLongTokenAmount`
- if `longTokenAmount >= diff` the result is an unbalanced pool since we are attributing too many tokens to the long amount. 
- if `longTokenAmount < diff` this case behaves correctly

The same issue occurs on line 404 for the case when there is a deficit in short tokens.

## Impact

There are two different negative impacts stated in the above depending on the conditions. The first is an overflow that will cause the transaction to revert.

The second impact is more severe as it will cause an unbalanced pool to be created. The impact is the deposit will have a significant price impact. The most noticable case is the initial deposit. The first deposit will will have `diff = 0` and `poolShortTokenAMount = poolLongTokenAmount = 0`. The impact is line 408-409 is executed which attributes all funds to the short pool and none to the long pool.

## Code Snippet

Function `getAdjustedLongAndShortTokenAmounts()`
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol#L381-L414

First occurence of the bug.
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol#L395

Second occurrence of the bug.
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/ExecuteDepositUtils.sol#L404

## Tool used

Manual Review

## Recommendation

The aim of the function is to reduce the difference between the `poolLongTokenAmount` and `poolShortTokenAmount`. We have `longTokenAmount` as the amount of funds contributed by the user. Therefore the correct solution should be to use `longTokenAmount` in the mentioned if statements.

```solidity
        if (poolLongTokenAmount < poolShortTokenAmount) {
            uint256 diff = poolLongTokenAmount - poolShortTokenAmount;


            if (diff < longTokenAmount) { //@audit fix
                adjustedLongTokenAmount = diff + (longTokenAmount - diff) / 2;
                adjustedShortTokenAmount = longTokenAmount - adjustedLongTokenAmount;
            } else {
                adjustedLongTokenAmount = longTokenAmount;
            }
        } else {
            uint256 diff = poolShortTokenAmount - poolLongTokenAmount;


            if (diff < longTokenAmount) { //@audit fix
                adjustedShortTokenAmount = diff + (longTokenAmount - diff) / 2;
                adjustedLongTokenAmount - longTokenAmount - adjustedShortTokenAmount;
            } else {
                adjustedLongTokenAmount = 0;
                adjustedShortTokenAmount = longTokenAmount;
            }
        }
```
