IllIllI

medium

# Insufficient oracle validation

## Summary

Most prices are provided by an off-chain oracle archive via signed prices, but a Chainlink oracle is still used for index prices. These prices are insufficiently validated.


## Vulnerability Detail

There is no freshness check on the timestamp of the prices, so old prices may be used if [OCR](https://docs.chain.link/architecture-overview/off-chain-reporting) was unable to push an update in time


## Impact

Old prices mean traders will get wrong PnL values for their positions, leading to liquidations or getting more/less than they should, at the expense of other traders and the liquidity pools.


## Code Snippet

The timestamp field is ignored, which means there's no way to check whether the price is recent enough:
```solidity
// File: gmx-synthetics/contracts/oracle/Oracle.sol : Oracle._setPricesFromPriceFeeds()   #1

571                (
572                    /* uint80 roundID */,
573                    int256 _price,
574                    /* uint256 startedAt */,
575 @>                 /* uint256 timestamp */,
576                    /* uint80 answeredInRound */
577:                ) = priceFeed.latestRoundData();
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L567-L587

## Tool used

Manual Review


## Recommendation

Add a staleness threshold number of seconds configuration parameter, and ensure that the price fetched is within that time range

