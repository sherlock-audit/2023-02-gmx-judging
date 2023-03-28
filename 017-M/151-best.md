IllIllI

medium

# Missing checks for whether Arbitrum Sequencer is active

## Summary

Chainlink recommends that users using price oracles, check whether the Arbitrum Sequencer is [active](https://docs.chain.link/data-feeds/l2-sequencer-feeds#arbitrum)


## Vulnerability Detail

If the sequencer goes down, the index oracles may have stale prices, since L2-submitted transactions (i.e. by the aggregating oracles) will not be processed.

## Impact

Stale prices, e.g. if USDC were to de-peg while the sequencer is offline, would let people submit orders and if those people are also keepers, get execution prices that do not exist in reality.

## Code Snippet

Chainlink oracles are used for some prices, but there are no sequencer oracles in use:

```solidity
// File: gmx-synthetics/contracts/oracle/Oracle.sol : Oracle._setPricesFromPriceFeeds()   #1

569                IPriceFeed priceFeed = getPriceFeed(dataStore, token);
570    
571                (
572                    /* uint80 roundID */,
573                    int256 _price,
574                    /* uint256 startedAt */,
575                    /* uint256 timestamp */,
576                    /* uint80 answeredInRound */
577                ) = priceFeed.latestRoundData();
578    
579:               uint256 price = SafeCast.toUint256(_price);
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L569-L579


## Tool used

Manual Review


## Recommendation

Use a [chainlink oracle](https://blog.chain.link/how-to-use-chainlink-price-feeds-on-arbitrum/#almost_done!_meet_the_l2_sequencer_health_flag) to determine whether the sequencer is offline or not, and don't allow orders to be executed while the sequencer is offline.
