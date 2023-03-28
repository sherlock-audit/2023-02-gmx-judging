IllIllI

medium

# Orders older than 255 blocks get canceled, losing their submitted prices

## Summary

Orders older than 255 blocks get canceled, losing their submitted prices. The hashes of oracle prices include the block timestamp. If an order is older than the `minBlockConfirmations` (currently set to [100](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/config/oracle.ts#L68)), then the order's block's hash is assigned so that the signature will only be validated after the minimum number of confirmations.


## Vulnerability Detail

The block hash assigned comes from a call to [Chain.getBlockHash()](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/chain/Chain.sol#L36-L39), which resolves to `blockhash()` or `arbSys.arbBlockHash()`, both of which [return zero](https://github.com/OffchainLabs/nitro/blob/47c8ba087ecae5e9f15a0375818848b14e98eca8/precompiles/ArbSys.go#L49-L55) if the block is older than 255 blocks.

If an order is older than 255 blocks (e.g. due to a keeper outage, or the feature being temporarily disabled, or a token being paused), then the oracle price signatures won't match, and the order will be canceled.


## Impact

User's orders that aim to exit a position may be delayed, causing their orders to be delayed, which will cause them to be canceled. Since the user's position will not have been closed, the user may get liquidated, even if they submitted a valid order in time.


## Code Snippet

Block hash is looked up at the time of the order, during the setting of the order's oracle prices:
```solidity
// File: gmx-synthetics/contracts/oracle/Oracle.sol : Oracle._setPrices()   #1

464                cache.info.blockHash = bytes32(0);
465                if (Chain.currentBlockNumber() - cache.info.minOracleBlockNumber <= cache.minBlockConfirmations) {
466 @>                 cache.info.blockHash = Chain.getBlockHash(cache.info.minOracleBlockNumber);
467                }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L454-L474

and the `blockHash` is included in the [oracle signature](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/OracleUtils.sol#L261).


## Tool used

Manual Review


## Recommendation

Do not include the `blockHash` in the signature, and instead, emit the oracle's `blockHash` during order execution, so that it can be checked manually after the fact, if there's an issue. If `oracleTimestamp` is not the block timestamp, include the block timestamp in the hash instead.


