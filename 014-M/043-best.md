csanuragjain

medium

# User deposit/withdrawal/order will get cancelled

## Summary
It was observed that an ORDER_KEEPER role can mistakenly cancel other user deposit/withdrawal/order due to missing error check. This is shown in detail for deposit case, but the similar poc is also valid for withdrawal and order case

## Vulnerability Detail
1. For this poc we will take deposit cancellation case
2. Lets say User A created a new deposit using `createDeposit` function. 
3. ORDER_KEEPER role proceeds to execute this deposit using `executeDeposit` function

```solidity
function executeDeposit(
        bytes32 key,
        OracleUtils.SetPricesParams calldata oracleParams
    ) external
        globalNonReentrant
        onlyOrderKeeper
        withOraclePrices(oracle, dataStore, eventEmitter, oracleParams)
    {
        uint256 startingGas = gasleft();

        try this._executeDeposit(
            key,
            oracleParams,
            msg.sender,
            startingGas
        ) {
        } catch (bytes memory reasonBytes) {
            _handleDepositError(
                key,
                startingGas,
                reasonBytes
            );
        }
    }
```

6. `_executeDeposit` tries to check `executeDepositFeatureDisabledKey` key. Lets say at current time deposit execution is currently disabled so FeatureUtils.validateFeature will revert with FeatureUtils.DisabledFeature error

```solidity
function _executeDeposit(
        bytes32 key,
        OracleUtils.SetPricesParams memory oracleParams,
        address keeper,
        uint256 startingGas
    ) external onlySelf {
        FeatureUtils.validateFeature(dataStore, Keys.executeDepositFeatureDisabledKey(address(this)));
...
}
```

7. This will call `_handleDepositError` (catch section) 

```
function _handleDepositError(
        bytes32 key,
        uint256 startingGas,
        bytes memory reasonBytes
    ) internal {
        (string memory reason, /* bool hasRevertMessage */) = ErrorUtils.getRevertMessage(reasonBytes);

        bytes4 errorSelector = ErrorUtils.getErrorSelectorFromData(reasonBytes);

        if (OracleUtils.isEmptyPriceError(errorSelector)) {
            ErrorUtils.revertWithCustomError(reasonBytes);
        }

        DepositUtils.cancelDeposit(
            ...
        );
    }
```

8. Now from this function it seems that on contract specific issues (like isEmptyPriceError), revert will happen. But there is no check to see if errorSelector is FeatureUtils.DisabledFeature, meaning the deposit will get cancelled (via cancelDeposit) instead of reverting which was not expected

## Impact
other users deposit, withdrawals and orders could be cancelled even though users never wanted the same. 

## Code Snippet
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/DepositHandler.sol#L188-L192
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/WithdrawalHandler.sol#L185-L189
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/OrderHandler.sol#L224-L231

## Tool used
Manual Review

## Recommendation
Kindly add check for FeatureUtils.DisabledFeature error as well in `_handleDepositError` function for deposit/withdrawal/order handler as this could be one of valid errorSelector
