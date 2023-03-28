IllIllI

medium

# Tracking of the latest ADL block use the wrong block number on Arbitrum

## Summary

Tracking of the latest ADL block use the wrong block number on Arbitrum


## Vulnerability Detail

The call to `setLatestAdlBlock()` passes in `block.timestamp`, which on Arbitrum, is the L1 block timestamp, not the L2 timestamp on which order timestamps are based.


## Impact

Tracking of whether ADL is currently required or not will be based on block numbers that are very far in the past (since Arbitrum block numbers are incremented much more quickly than Ethereum ones), so checks of whether ADL is enabled will pass, and the ADL keeper will be able to execute ADL orders whenever it wants to.


## Code Snippet

Uses `block.number` rather than [`Chain.currentBlockNumber()`](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/chain/Chain.sol#L24-L30
):
```solidity
// File: gmx-synthetics/contracts/adl/AdlUtils.sol : AdlUtils.updateAdlState()   #1

104            MarketUtils.MarketPrices memory prices = MarketUtils.getMarketPrices(oracle, _market);
105            (bool shouldEnableAdl, int256 pnlToPoolFactor, uint256 maxPnlFactor) = MarketUtils.isPnlFactorExceeded(
106                dataStore,
107                _market,
108                prices,
109                isLong,
110                Keys.MAX_PNL_FACTOR
111            );
112    
113            setIsAdlEnabled(dataStore, market, isLong, shouldEnableAdl);
114 @>         setLatestAdlBlock(dataStore, market, isLong, block.number);
115    
116            emitAdlStateUpdated(eventEmitter, market, isLong, pnlToPoolFactor, maxPnlFactor, shouldEnableAdl);
117:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/adl/AdlUtils.sol#L104-L117

The block number (which is an L1 block number) is checked against the L2 oracle [block numbers](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/adl/AdlUtils.sol#L192-L195).


## Tool used

Manual Review


## Recommendation

Use `Chain.currentBlockNumber()` as is done everywhere else in the code base
