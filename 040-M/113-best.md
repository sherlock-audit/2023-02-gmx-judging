Breeje

medium

# Multiplication after Division error leading to larger precision loss

## Summary

There are couple of instance of using result of a division for multiplication while can cause larger precision loss.

## Vulnerability Detail

```solidity
File: MarketUtils.sol

948:    cache.fundingUsd = (cache.sizeOfLargerSide / Precision.FLOAT_PRECISION) * cache.durationInSeconds * cache.fundingFactorPerSecond;

952:    if (result.longsPayShorts) {
953:          cache.fundingUsdForLongCollateral = cache.fundingUsd * cache.oi.longOpenInterestWithLongCollateral / cache.oi.longOpenInterest;
954:          cache.fundingUsdForShortCollateral = cache.fundingUsd * cache.oi.longOpenInterestWithShortCollateral / cache.oi.longOpenInterest;
955:      } else {
956:          cache.fundingUsdForLongCollateral = cache.fundingUsd * cache.oi.shortOpenInterestWithLongCollateral / cache.oi.shortOpenInterest;
957:          cache.fundingUsdForShortCollateral = cache.fundingUsd * cache.oi.shortOpenInterestWithShortCollateral / cache.oi.shortOpenInterest;
958:      }

```
[Link to Code](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/market/MarketUtils.sol#L948)


In above case, value of `cache.fundingUsd` is calculated by first dividing `cache.sizeOfLargerSide` with `Precision.FLOAT_PRECISION` which is `10**30`. Then the resultant is multiplied further. This result in larger Loss of precision.

Later the same `cache.fundingUsd` is used to calculate `cache.fundingUsdForLongCollateral` and `cache.fundingUsdForShortCollateral` by multiplying further which makes the precision error even more big.

Same issue is there in calculating `cache.positionPnlUsd` in `PositionUtils`.

```solidity
File: PositionUtils.sol

    if (position.isLong()) {
            cache.sizeDeltaInTokens = Calc.roundUpDivision(position.sizeInTokens() * sizeDeltaUsd, position.sizeInUsd());
        } else {
            cache.sizeDeltaInTokens = position.sizeInTokens() * sizeDeltaUsd / position.sizeInUsd();
        }
    }

    cache.positionPnlUsd = cache.totalPositionPnl * cache.sizeDeltaInTokens.toInt256() / position.sizeInTokens().toInt256();

```
[Link to Code](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/position/PositionUtils.sol#L217-L224)

## Impact

Precision Loss in accounting.

## Code Snippet

Given above.

## Tool used

Manual Review

## Recommendation

First Multiply all the numerators and then divide it by the product of all the denominator.
