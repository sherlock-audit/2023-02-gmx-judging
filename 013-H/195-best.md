berndartmueller

medium

# Underestimated gas estimation for executing withdrawals leads to insufficient keeper compensation

## Summary

The `GasUtils.estimateExecuteWithdrawalGasLimit` function underestimates the gas estimation for withdrawal execution, as it does not take into account token swaps, unlike the gas estimation in the `GasUtils.estimateExecuteDepositGasLimit` function (used to estimate executing deposits).

## Vulnerability Detail

When creating a withdrawal request, the `WithdrawalUtils.createWithdrawal` function estimates the gas required to execute the withdrawal and validates that the paid execution fee (`params.executionFee`) is sufficient to cover the estimated gas and to compensate the keeper executing the withdrawal fairly.

However, the `GasUtils.estimateExecuteWithdrawalGasLimit` function used to estimate the gas for executing withdrawals does not account for token swaps that can occur at the end of the withdrawal logic and therefore underestimates the gas estimation.

Token swaps are performed in the `WithdrawalUtils._executeWithdrawal` function in lines 354 and 365.

## Impact

The keeper executing withdrawals receives fewer execution fees and is not fully compensated for the gas spent. Moreover, users can pay fewer execution fees than expected and required.

## Code Snippet

[contracts/gas/GasUtils.sol#L150](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/gas/GasUtils.sol#L150)

The gas estimate calculated in the `GasUtils.estimateExecuteWithdrawalGasLimit` function only uses a static gas limit plus the callback gas limit. Token swaps are not accounted for.

```solidity
149: function estimateExecuteWithdrawalGasLimit(DataStore dataStore, Withdrawal.Props memory withdrawal) internal view returns (uint256) {
150:     return dataStore.getUint(Keys.withdrawalGasLimitKey(false)) + withdrawal.callbackGasLimit();
151: }
```

[contracts/withdrawal/WithdrawalUtils.createWithdrawal() - L163](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/withdrawal/WithdrawalUtils.sol#L163)

As observed in the `createWithdrawal` function, the `GasUtils.estimateExecuteWithdrawalGasLimit` function estimates the gas required to execute the withdrawal and validates the paid execution fee accordingly.

```solidity
110: function createWithdrawal(
111:     DataStore dataStore,
112:     EventEmitter eventEmitter,
113:     WithdrawalVault withdrawalVault,
114:     address account,
115:     CreateWithdrawalParams memory params
116: ) external returns (bytes32) {
...      // [...]
160:
161:     CallbackUtils.validateCallbackGasLimit(dataStore, withdrawal.callbackGasLimit());
162:
163:     uint256 estimatedGasLimit = GasUtils.estimateExecuteWithdrawalGasLimit(dataStore, withdrawal);
164:     GasUtils.validateExecutionFee(dataStore, estimatedGasLimit, params.executionFee);
165:
166:     bytes32 key = NonceUtils.getNextKey(dataStore);
167:
168:     WithdrawalStoreUtils.set(dataStore, key, withdrawal);
169:
170:     WithdrawalEventUtils.emitWithdrawalCreated(eventEmitter, key, withdrawal);
171:
172:     return key;
173: }
```

[contracts/withdrawal/WithdrawalUtils.executeWithdrawal() - L206-L213](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/withdrawal/WithdrawalUtils.sol#L206-L213)

The execution fee is paid to the keeper at the end of the `executeWithdrawal` function.

```solidity
180: function executeWithdrawal(ExecuteWithdrawalParams memory params) external {
181:     Withdrawal.Props memory withdrawal = WithdrawalStoreUtils.get(params.dataStore, params.key);
...      // [...]
205:
206:     GasUtils.payExecutionFee(
207:         params.dataStore,
208:         params.withdrawalVault,
209:         withdrawal.executionFee(),
210:         params.startingGas,
211:         params.keeper,
212:         withdrawal.account()
213:     );
214: }
```

## Tool used

Manual Review

## Recommendation

Consider incorporating the token swaps in the gas estimation for withdrawal execution, similar to how it is done in the `GasUtils.estimateExecuteDepositGasLimit` function.
