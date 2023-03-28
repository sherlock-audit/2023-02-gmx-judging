0xdeadbeef

high

# Deposits/Withdrawals/Orders will be canceled if created before feature is disabled and attempted to be executed after

## Summary

The protocol has the ability to enable/disable operations such as deposits, withdrawals and orders. 

If the the above operations are disabled:
1. Users will not be able to create/cancel the operations
2. Keepers will not be able to execute the operations

However - on execution failure, cancellation will succeed even if the feature is disabled.

Therefore - keepers executing operations that are disabled will cancel them and make the user pay execution fees. (loss of funds) 
 

## Vulnerability Detail

Let us use deposits as an example. Other operations behave in a similar way. 

Consider the following scenario:
1. Bob creates a deposit using `createDeposit`
2. GMX disabled deposits because of maintenance.
3. Keeper executed Bobs deposit
4. Bobs deposit is cancelled and the execution fee is paid to the keeper from Bobs pocket.
5. GMX finished maintenance and enables again the deposits

Execution will fail in the following check:
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/DepositHandler.sol#L144-L150 

The revert will be caught in the catch statement and `_handleDepositError` will be called:
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/DepositHandler.sol#L102-L113

`_handleDepositError` will call `DepositUtils.cancelDeposit` which does not have feature validation:
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/DepositHandler.sol#L181-L203

## Impact

Users lose execution fee funds and have to deposit again.

## Code Snippet

## Tool used

Manual Review

## Recommendation

For each operation:
1. add a customer error to catch and revert the feature disable reason, like empty price is caught: https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/exchange/DepositHandler.sol#L190
2. Add the feature check in the internal `DepositUtils.cancelDeposit` functions 
