IllIllI

medium

# Requests to not send wrapped tokens are ignored during failures

## Summary

GMX has the ability to interact with both native tokens, and wrapped native tokens, and allows the user to specify which asset they want to use.


## Vulnerability Detail

If there is a failure during the sending of the native asset, even if the user explicitly says they do not want the wrapped version, the native asset is wrapped anyway and sent to them. Note that this is the recipient address, not the original account address.

## Impact

The recipient may not be able to handle wrapped native tokens (e.g. it's a smart contract, or an exchange address that only supports native tokens), and once sent, the wrapped version will be lost forever


## Code Snippet

The withdrawal code that asks whether to [only send the native tokens](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/bank/Bank.sol#L61) eventually calls this function, which re-wrapps on failure:
```solidity
// File: gmx-synthetics/contracts/token/TokenUtils.sol : TokenUtils.withdrawAndSendNativeToken()   #1

133            (bool success, /* bytes memory data */) = payable(receiver).call{ value: amount, gas: gasLimit }("");
134    
135            if (success) { return; }
136    
137            // if the transfer failed, re-wrap the token and it to the receiver
138 @>         depositAndSendWrappedNativeToken(
139                dataStore,
140                receiver,
141                amount
142            );
143:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/token/TokenUtils.sol#L133-L143


## Tool used

Manual Review


## Recommendation

Revert the transaction, or allow for a two-step withdrawal, where the user withdraws funds from the pool, but can do the actual claim later.
