IllIllI

medium

# Order keepers will be forced to waste gas on orders that revert

## Summary

The readme states:
```markdown
Order keepers are expected to validate whether a transaction will revert before sending the transaction to minimize gas wastage
```
https://github.com/sherlock-audit/2023-02-gmx-IllIllI000/tree/master/gmx-synthetics#known-issues

And the project provides `simulate*()` for accomplishing these checks, and each one's NatSpec says the purpose is to `simulate execution of an order to check for any errors`. 


## Vulnerability Detail

The `simulate*()` functions properly fill prices via the `withSimulatedOraclePrices()` modifier, but do not fill any signer/block information, so checks for things like the [minimum](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L225) number of signers, or [block/time](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L444-L467) information will fail.


## Impact

The functions do not work and will revert every time, which means that either orders won't be executed by keepers, or keepers will have to guess and waste gas on transactions that may revert. Keepers will not be economical and will lose gas and eventually exit the keeper market.


## Code Snippet

Simulation passes an uninitialized `oracleParams` struct:
```solidity
// File: gmx-synthetics/contracts/exchange/OrderHandler.sol : OrderHandler.simulateExecuteOrder()   #1

143        function simulateExecuteOrder(
144            bytes32 key,
145            OracleUtils.SimulatePricesParams memory params
146        ) external
147            onlyController
148            withSimulatedOraclePrices(oracle, params)
149            globalNonReentrant
150        {
151            uint256 startingGas = gasleft();
152    
153 @>         OracleUtils.SetPricesParams memory oracleParams;
154    
155            this._executeOrder(
156                key,
157                oracleParams,
158                msg.sender,
159                startingGas
160            );
161:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/OrderHandler.sol#L143-L161

An empty struct will revert because the tokens array [is empty](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/oracle/Oracle.sol#L214-L220), as well as for the reasons linked to above.


## Tool used

Manual Review


## Recommendation

Simulation params should have all of the fields a normal SetPricesParams has, and use that to fill in `oracleParams`

