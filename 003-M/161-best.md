IllIllI

medium

# Paying with native tokens does not work

## Summary

Paying with native tokens does not work

## Vulnerability Detail

The `createDeposit()` and `createWithdrawal()` functions are `payable` functions in order to let users pay with native tokens, and the multicall version also supports native tokens, but `wnt.deposit()` is never called anywhere, to convert to to an ERC20 token.


## Impact

If the feature is intended to work, as opposed to being an oversight, one way a user can lose funds is to send the majority of execution fees as WNT that they have on hand, but a small fraction to top off the remaining execution fee. If, by the time they've submitted their order, the gas fee has diminished, the user won't get back the full gas refund that they deserve, because gas refunds are based solely on the deposited [WNT balance](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/withdrawal/WithdrawalUtils.sol#L118).


## Code Snippet

Both payable, and neither does a conversion:
```solidity
// File: gmx-synthetics/contracts/router/ExchangeRouter.sol : ExchangeRouter.createDeposit()   #1

115        function createDeposit(
116            DepositUtils.CreateDepositParams calldata params
117:@>     ) external payable nonReentrant returns (bytes32) {
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/router/ExchangeRouter.sol#L115-L117

```solidity
// File: gmx-synthetics/contracts/router/ExchangeRouter.sol : ExchangeRouter.createWithdrawal()   #2

142        function createWithdrawal(
143            WithdrawalUtils.CreateWithdrawalParams calldata params
144:@>     ) external payable nonReentrant returns (bytes32) {
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/router/ExchangeRouter.sol#L142-L151


## Tool used

Manual Review


## Recommendation

If native tokens are to be supported, add deposit calls for `msg.value`

