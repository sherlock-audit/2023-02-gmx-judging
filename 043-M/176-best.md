IllIllI

medium

# Delayed orders won't use correct prices

## Summary

GMX uses two oracle types - an off-chain oracle archive network for historical prices of tokens whose value fluctuates a lot, and a set of price feed oracles for tokens that don't change value much. The oracle archive network allows people to submit orders at time T, and have them executed at time T+N, while still getting filled at prices at time T.


## Vulnerability Detail

The majority of markets use prices from both types of oracles, and if one of the price feed oracle's tokens de-peg, (e.g. UST, or the recent USDC depeg), users whose orders are delayed by keepers will get executed at different prices than they deserve.


## Impact

Delayed prices during a depeg event means they get more/less PnL than they deserve/liquidations, at the expense of traders or the liquidity pool


## Code Snippet

Prices for the order will use the current value, rather than the value at the time the order was submitted:
```solidity
// File: gmx-synthetics/contracts/oracle/Oracle.sol : Oracle._setPricesFromPriceFeeds()   #1

571                (
572                    /* uint80 roundID */,
573 @>                 int256 _price,
574                    /* uint256 startedAt */,
575                    /* uint256 timestamp */,
576                    /* uint80 answeredInRound */
577                ) = priceFeed.latestRoundData();
...
588                uint256 stablePrice = getStablePrice(dataStore, token);
589    
590                Price.Props memory priceProps;
591    
592                if (stablePrice > 0) {
593                    priceProps = Price.Props(
594                        price < stablePrice ? price : stablePrice,
595                        price < stablePrice ? stablePrice : price
596                    );
597                } else {
598 @>                 priceProps = Price.Props(
599                        price,
600                        price
601                    );
602                }
603    
604:@>             primaryPrices[token] = priceProps;
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L571-L604

Presumably, there won't be archive oracle prices for tokens that have these price feeds, since that would allow the keeper to decide to use whichever price is more favorable to them, so once there's a de-peg, any outstanding orders will be affected.


## Tool used

Manual Review


## Recommendation

Don't use Chainlink oracle for anything, and instead rely on the archive oracles for everything

