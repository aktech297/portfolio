
# Audit Report - Tigris Trade Options

|             |                                                      |
| ----------- | ---------------------------------------------------- |
| **Date**    | May 2023                                              |
| **Auditor** | bytes032 ([@bytes032](https://twitter.com/bytes032)) |
| **Website** | https://bytes032.xyz/                                |


# About Tigris

[Tigris](https://app.tigris.trade/) is a leveraged trading platform that utilizes price data signed by oracles off-chain to provide atomic trades and real-time pair prices.

Open positions are minted as NFTs, making them transferable. Tigris is governed by TIG token holders.

The oracle aggregates real-time spot market prices from CEXs and sign them. Traders include the price data and signature in the trade txs.

For people that want to provide liquidity, they can lock up tigAsset tokens (such as tigUSD, received by depositing the appropriate token into the stablevault) for up to 365 days.

They receive 30% of trading fees, which are distributed based on amount locked and lock period.

# Table of Contents

- [Scope](#scope)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Severity classification](#severity-classification)
- [Summary](#summary)
- [Findings](#findings)

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Severity classification

| Severity         | Description                                                                                                                                                                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ![](https://camo.githubusercontent.com/a0b140cbe7b198d62804d91996e3c09c6803cfbd484c61974af51892481f840e/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f2d437269746963616c2d643130623062)            | A **directly** exploitable security vulnerability that leads to stolen/lost/locked/compromised assets or catastrophic denial of service.                                                                                                       |
| ![](https://camo.githubusercontent.com/77229c2f86cd6aaaaaeb3879eac44712b0e095147962e9058e455d0094f500d3/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f2d486967682d726564)             | A security vulnerability or bug that can affect the correct functioning of the system, lead to incorrect states or denial of service. It may not be directly exploitable or may require certain, external conditions in order to be exploited. |
| ![](https://camo.githubusercontent.com/d2cf6c2836b2143aeeb65c08b9c5aa1eb34a6fb8ad6fc55ba4345c467b64378a/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f2d4d656469756d2d6f72616e6765)        | Assets not at direct risk, but the function of the protocol or its availability could be impacted, or leak value with a hypothetical attack path with stated assumptions, but external requirements.                                           |
| ![](https://camo.githubusercontent.com/d42acfb8cb8228c156f34cb1fab83f431bf1fbebc102d922950f945b45e05587/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f2d4d696e6f722d79656c6c6f77)         | A violation of common best practices or incorrect usage of primitives, which may not currently have a major impact on security, but may do so in the future or introduce inefficiencies.                                                       |


# Scope

The review focused on the following commit hash [`hash`](47bf1157f87d4db12066cfb5e8f25e8571b7d2c0).
The following contracts were in scope of the audit:

| File           | Code |
| -------------- | ---- |
| ./Options.sol  | 462  |
| ./TradeNFT.sol | 186  |
| ---      | --- |
| Total:        | 648     |


NSLOC stands for 'Normalized Source Code', which is a custom measurement I use (among others) when evaluating the complexity of a codebase.

To get the NSLOC count of a file I do the following:
1.  For all functions, reduce any multiline function declarations to a single line.
2.  Remove all comments
3.  Remove all empty lines
4.  Count the remaining lines

# Summary

The audited contracts contain **4 critical** issues, **2 high severity** issues, **1 medium** severity issues and **2 minor** issues.

| #   |                                                                Title                                                                |                                                                                           Severity                                                                                            | Status                                                                                                                                                                                                  |
| --- |:-----------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 | Limit order expiry time flaw could lead to loss of funds | ![](https://img.shields.io/badge/-Critical-d10b0b) | ![](https://img.shields.io/badge/-Resolved-brightgreen)  | 
| 2 | It's possible to open a trade in the same tx with two different prices | ![](https://img.shields.io/badge/-Critical-d10b0b) | ![](https://img.shields.io/badge/-Resolved-brightgreen) | 
| 3 | Price validation vulnerability in closeTrade | ![](https://img.shields.io/badge/-Critical-d10b0b) | ![](https://img.shields.io/badge/-Resolved-brightgreen)  | 
| 4 | openInterest can grow infinitely | ![](https://img.shields.io/badge/-High-red) | ![](https://img.shields.io/badge/-Resolved-brightgreen) | 
| 5 | A malicious user can open orders exceeding the maximum possible amount   | ![](https://img.shields.io/badge/-High-red) | ![](https://img.shields.io/badge/-Resolved-brightgreen)  | 
| 6 | closeTrade can deprive users of their rewards  | ![](https://img.shields.io/badge/-High-red) | ![](https://img.shields.io/badge/-Resolved-brightgreen)  | 
| 7 |  No check for active Arbitrum Sequencer in getVerifiedPrice | ![](https://img.shields.io/badge/-Medium-orange) | ![](https://img.shields.io/badge/-Acknowledged-grey) | 
| 8 | Missing asset existence check   | ![](https://img.shields.io/badge/-Minor-yellow) | ![](https://img.shields.io/badge/-Acknowledged-grey) |
| 9 | Redundant TradeAsset variables   | ![](https://img.shields.io/badge/-Minor-yellow) | ![](https://img.shields.io/badge/-Acknowledged-grey) |

# Findings

## Critical Risk Findings (3)

### 1. Limit order expiry time flaw could lead to loss of funds ![](https://img.shields.io/badge/-Critical-d10b0b) ![](https://img.shields.io/badge/-Resolved-brightgreen)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L256-L262)

**Impact**

The vulnerability discovered could lead to significant financial loss for users. In the event that an order is not executed within its specified duration, it can still be executed after the expiry time. This execution could be at an unfavorable price, leading to direct loss of funds.

**Description**

Right now, a limit order can be initiated with a specific duration, which respectively populates the `expires` variable when the trade is [minted](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/TradeNFT.sol#L105-L107).

```solidity
        newTrade.duration = _mintTrade.duration;
        newTrade.openPrice = _mintTrade.price;
        newTrade.expires = _mintTrade.duration + block.timestamp;
```

This variable is crucial, because it's used in `closeTrade` to ensure that the trade can only be closed when it's duration has expired.

```solidity        
        if (block.timestamp < _trade.expires) revert("!expired");
```

For instance, let's consider the following steps:

1.  A user initiates a limit order with a `duration = x`, setting the `expiry = x + block.timestamp`.
2.  For some reason, the order cannot be executed for the whole duration, e.g., it enters into one of the `if (trade.openPrice > _price) revert("!limitPrice");` conditions.
3.  When the expiry time has passed, the order can now be executed. As soon as it gets executed, it can immediately be closed, because the condition `if (block.timestamp < _trade.expires) revert("!expired");` no longer holds.
4.  Depending on the asset's price at the time of execution, this will lead to a direct loss of funds.

**Recommendation**

To address this vulnerability, it's advised to refactor the function so that `initiateLimitOrder` sets `expires` to 0, irrespective of the duration. Then, `expires` should be updated when the order is executed. This change would prevent orders from being executed after their duration has expired.

Furthermore, it would be beneficial to enforce a minimum duration (e.g., 30 seconds). This would provide a buffer to prevent the immediate execution and closure of trades, allowing users to react to market changes.

**Resolution:**

[Fixed](https://github.com/Tigris-Trade/Contracts/commit/7e49dd168345992eedf4e932c024fd110e671b6a)

### 2. It's possible to open a trade in the same tx with two different prices ![](https://img.shields.io/badge/-Critical-d10b0b) ![](https://img.shields.io/badge/-Resolved-brightgreen)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L315)

Tigris utilizes oracle nodes which are connected to the [Pythnet](https://pyth.network) price feed. The asset prices and other related data is signed and broadcasted directly to Tigris users, which is used to place market orders. This data consists of:

-   Asset price
-   Spread
-   Timestamp
-   Node address
-   Market open/closed status
-   Oracle signature

Upon placing a trade, price data and signature is included in the transaction input parameters, where the validity of the data and the signatures are verified on-chain.

This means there could be two different prices in the "valid signature pool" at the same time.

In `Options.sol`, the price of the asset is fetched through `getVerifiedPrice`

```solidity
        _price = _priceData.price;
        _spread = _priceData.spread;

        if(_withSpreadIsLong == 1 && useSpread) 
            _price += _price * _spread / DIVISION_CONSTANT;
        else if(_withSpreadIsLong == 2 && useSpread) 
            _price -= _price * _spread / DIVISION_CONSTANT;
```

If a spread is set, it will update the price according to that, e.g. if price is 1000 and spread is 0.1% the long trades will open with price 1001 and short trades will open with price 999.

Otherwise, it will just return the price as is.

When you open a trade, you can specify duration, which is then derived to set the expiration of the trade.

```solidity
>       newTrade.duration = _mintTrade.duration;
        newTrade.openPrice = _mintTrade.price;
>        newTrade.expires = _mintTrade.duration + block.timestamp;
```

Then, when closing a trade the `expiry` variable is used to ensure that only trades which expired can be closed.

```solidity
 function closeTrade(
        uint256 _id,
        PriceData calldata _priceData,
        bytes calldata _signature
    )
        external
    {
    ...

>     if (block.timestamp < _trade.expires) revert("!expired");
    ...
```

The catch here is that as per Arbitrum's [docs](https://github.com/OffchainLabs/arbitrum/blob/master/docs/Time_in_Arbitrum.md#ethereum-block-numbers-within-arbitrum), any timing assumptions a contract makes about block numbers and timestamps should be considered generally reliable in the longer term (i.e., on the order of at least several hours) but unreliable in the shorter term (minutes)

It is unreliable in a shorter term, because if multiple Arbitrum transactions are in a single L1 block, they **will** have the same block.timestamp.

This means around 20 transactions in Arbitrum can have the same block timestamp.

Running
```bash
cast block --rpc-url https://arb-mainnet.g.alchemy.com/v2/UVXidxBjyLOdMXEJxYtCMqqEkHATR2gQ 17169970
```

Yields the following result:

![](https://i.imgur.com/aDbctFl.png)


Then, running the script for 20 blocks further
```bash
cast block --rpc-url https://arb-mainnet.g.alchemy.com/v2/UVXidxBjyLOdMXEJxYtCMqqEkHATR2gQ 17169970
```

Yields the following result:
![](https://i.imgur.com/VF0RV3c.png)

This proves that 20 distinct transactions in Arbitrum can have the same timestamp.

Back to openTrade and closeTrade, this essentially means a user can open/close trade in the same **L1 block**.

Consider the following scenario:
1. useSpread is not set, so the oracle returns the price as is.
2. Amelie opens a trade with where `duration = 0` and `collateral = 1e18` and she picks price X from the pool. Because duration is set to 0, this means expiry = block.timestamp.
3. Immediately, in the same or after the first transaction, she closes her trade, which is possible because `block.timestamp == trade.expiry`, but now picks price Y from the pool, where Y > X.
4. $

Picking a different price from the pool is possible, because anyone can get signed prices. Additionally, the price **timestamp** is not chain dependant, but is generated from the node that is signing the prices.

Hence, the check below will pass for ~20-25 blocks in Arbitrum, because the block.timestamp will be the same, allowing the user to either open/close trades in the same transaction, or do it sequentially, while picking a more favorable price for the closing trade.

```solidity
function getVerifiedPrice(
        uint256 _asset,
        PriceData calldata _priceData,
        bytes calldata _signature,
        uint256 _withSpreadIsLong,
        bool _expirable
    ) 
        public view
        returns(uint256 _price, uint256 _spread) 
    {
        ...
        if(_expirable) require(block.timestamp <= _priceData.timestamp + _validSignatureTimer, "ExpSig");
        ....
```

**Recommendation:**

Update the condition in the `closeTrade` function to prevent a trade from being closed within the same L1 block. You can achieve this by adding a condition to check if the current `block.timestamp` is greater than `_trade.expires`. Here is the suggested change:

```diff
+     if (block.timestamp <= _trade.expires) revert("!expired");
```

This modification will inhibit the possibility of making profitable transactions by opening and closing a trade within the same block using two different prices from the "valid signature pool".

**Resolution:**

[Fixed](https://github.com/Tigris-Trade/Contracts/commit/74487297c7e3c318855cb3cd2da5378773c3d4e7)

### 3. Price validation vulnerability in closeTrade ![](https://img.shields.io/badge/-Critical-d10b0b) ![](https://img.shields.io/badge/-Resolved-brightgreen)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L315)

**Impact:**

This vulnerability could lead to the manipulation of trade outcomes by the users, potentially allowing them to win trades unfairly. As such, it could undermine the integrity of the trading system and expose the Tigris-Trade platform to reputational damage and potential financial losses.

**Description:**

The `closeTrade` function in the Tigris-Trade `Options.sol` contract currently bypasses price expiration checks, enabling users to close trades with potentially stale price data. This is made possible because the `getVerifiedPrice` function call within `closeTrade` has the `_expirable` parameter set to `false`. This means that the timestamp of the price data is not being checked against the current block timestamp.

This could allow users to open a trade at the current price and then close it with a potentially outdated price, essentially gaming the system. In the context of a price expiration condition that should typically prevent this, this can be considered a major security oversight.

The vulnerable code is located here:
```solidity
(uint256 _price,) = getVerifiedPrice(_trade.asset, _priceData, _signature, 0, false);
```

In practice, this means a user can open a trade with whatever the current price is and then select a price that could be days old, but one that will consider the trade as a win.

```solidity
       bool isWin;
        if (_trade.direction && _price > _trade.openPrice) {
            isWin = true;
        } else if(!_trade.direction && _price < _trade.openPrice) {
            isWin = true;
        }
```

**Recommendation:**

To mitigate this vulnerability, it's recommended to activate the price expiration checks in the `closeTrade` function. This could be done by setting the `_expirable` parameter to `true` when calling the `getVerifiedPrice` function in `closeTrade`.

The updated code should be as follows:
```solidity
(uint256 _price,) = getVerifiedPrice(_trade.asset, _priceData, _signature, 0, true);
```

**Resolution:**

[Fixed](https://github.com/Tigris-Trade/Contracts/commit/09a12b0546815485c5ce6b78d3c516dba4814ff3)

## High Risk Findings (3)

### 4. openInterest can grow infinitely ![](https://img.shields.io/badge/-High-red) ![](https://img.shields.io/badge/-Resolved-brightgreen)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L48)

**Impact:**

This issue could lead to a perpetual increase in openInterest for a specific traded asset without an appropriate mechanism to decrease it upon trade closure. This flaw can lead to permanent locking of an asset from trading, disrupting the normal operations of the contract and impacting the platform's liquidity and usability.

**Description**

The `TradedAsset` struct within `Options.sol` is employed to whitelist assets for options trading, setting critical parameters and constraints for such trades.

```

```solidity
    struct TradedAsset {
        uint maxCollateral;
        uint minCollateral;
        uint maxDuration;
        uint minDuration;
        uint maxOpen;
        uint openInterest;
        uint assetId;
        uint winPercent;
        uint closeFee;
        uint botFee;
        uint refFee;
    }
```

During the execution of a new trade or a limit order, the `openInterest` is properly increased:

```solidity
asset.openInterest += _tradeInfo.collateral;
```

```solidity
        TradedAsset storage asset = tradedAssets[trade.asset];
        asset.openInterest += trade.collateral;
```

This is crucial to ensure that the next open trades/limit orders won't exceed the maximum allowed open orders for that specific asset in both `openTrade` and `executeLimitOrder`


```solidity
    function openTrade(
        TradeInfo calldata _tradeInfo,
        PriceData calldata _priceData,
        bytes calldata _signature,
        ERC20PermitData calldata _permitData,
        address _trader
    )
        external
    {
        _validateProxy(_trader);
        TradedAsset storage asset = tradedAssets[_tradeInfo.asset];
        
        // asset.openInterest is 0 on creation
        require(asset.openInterest + _tradeInfo.collateral <= asset.maxOpen, "!maxOpen");
        require(_tradeInfo.collateral <= asset.maxCollateral, "!max");
        require(_tradeInfo.collateral >= asset.minCollateral, "!min");
```

```solidity
    function initiateLimitOrder(
        TradeInfo calldata _tradeInfo,
        uint256 _orderType, // 1 limit, 2 stop
        uint256 _price,
        ERC20PermitData calldata _permitData,
        address _trader
    )
        external
    {   
        TradedAsset storage asset = tradedAssets[_tradeInfo.asset];
        require(asset.openInterest + _tradeInfo.collateral <= asset.maxOpen, "!maxOpen");
        require(_tradeInfo.collateral <= asset.maxCollateral, "!max");
        require(_tradeInfo.collateral >= asset.minCollateral, "!min");

```

However, the contract doesn't provide a corresponding decrement operation when a trade is closed. This omission allows `openInterest` to grow indefinitely until it reaches the `maxOpen` limit, which blocks any new trades for that asset.

**Recommendation:**

It is recommended to decrement the `openInterest` value appropriately when a trade is closed. The following change should be made to decrease `openInterest` by the amount of the trade's collateral before the token for the position is burned:

```diff
+        _tradedAsset.openInterest -= _trade.collateral;
        tradeNFT.burn(_id);
        emit TradeClosed(_id, _price, isWin ? _tradedAsset.winPercent : 0, toSend, _trade.trader, _msgSender());
```

**Resolution:**

[Fixed](https://github.com/Tigris-Trade/Contracts/commit/afa627283d8f2bc641702cf7af709dfdb991e16b)

### 5. A malicious user can open orders exceeding the maximum possible amount ![](https://img.shields.io/badge/-High-red) ![](https://img.shields.io/badge/-Resolved-brightgreen)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L198-L211)

**Impact:**

This vulnerability can lead to a significant imbalance in the platform's liquidity management. It allows a malicious user to overcommit resources, potentially destabilizing the system by surpassing the `maxOpen` limit set for an asset.

**Description:**

The described vulnerability lies within the `initiateLimitOrder` function, which initiates limit orders based on the current `openInterest` of the asset. However, the current design does not immediately update the `openInterest` at the time of initiating an order.

```solidity
    function initiateLimitOrder(
        TradeInfo calldata _tradeInfo,
        uint256 _orderType, // 1 limit, 2 stop
        uint256 _price,
        ERC20PermitData calldata _permitData,
        address _trader
    )
        external
    {   
        TradedAsset storage asset = tradedAssets[_tradeInfo.asset];
        require(asset.openInterest + _tradeInfo.collateral <= asset.maxOpen, "!maxOpen");
        require(_tradeInfo.collateral <= asset.maxCollateral, "!max");
        require(_tradeInfo.collateral >= asset.minCollateral, "!min");

```

Instead, it is updated at a later stage when executing the order.

```solidity
        TradedAsset storage asset = tradedAssets[trade.asset];
        asset.openInterest += trade.collateral;
```

The problem arises from the fact that when several orders are initiated simultaneously before execution, the check is performed on the same, stale `openInterest` value.

As a result, a user can initiate multiple limit orders which, collectively, would exceed the `maxOpen` limit set for the asset. This situation is not prevented, as each check when initiating an order only considers the `openInterest` at the moment of initiating the order, ignoring subsequent changes due to other orders.

This scenario can be illustrated as follows:
1.  Assume `maxOpen = 5e18` and `openInterest = 0`.
2.  In a single transaction, Amelie initiates 5 limit orders with 5e18 collateral each.
3.  Each `initiateLimitOrder` call passes the check, as it is performed with the stale `openInterest` value.
4.  Amelie then executes these 5 transactions, resulting in `openInterest = 25e18`, which significantly exceeds the `maxOpen` limit set by the protocol.

**Recommendation:**

To mitigate this vulnerability, the `openInterest` variable should be updated in real-time as each order is initiated, not at the point of execution. This way, each subsequent `initiateLimitOrder` check would consider the most recent `openInterest` value, including all initiated but not yet executed orders.

Alternatively, if the protocol insists to use the current approach, the following checks should be performed right before execution again:

```solidity
        require(asset.openInterest + _tradeInfo.collateral <= asset.maxOpen, "!maxOpen");
        require(_tradeInfo.collateral <= asset.maxCollateral, "!max");
        require(_tradeInfo.collateral >= asset.minCollateral, "!min");
```

**Resolution:**

[Fixed](https://github.com/Tigris-Trade/Contracts/commit/5c6c6e0e034e4dd27d36d58de1a9455f72642d5d)

### 6. closeTrade can deprive users of their rewards ![](https://img.shields.io/badge/-High-red)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L321)

**Impact:**

The vulnerability affects the determination of winning trades, potentially leading to incorrect outcomes and depriving users of their rewards.

**Description:**

In Tigris's options implementation, users either lose 100% or win 70% (win percent) of their pledged collateral.

The "winning" formula looks like this:
```solidity

    function closeTrade(
        uint256 _id,
        PriceData calldata _priceData,
        bytes calldata _signature
    )
        external
    {
        ...
        bool isWin;
        if (_trade.direction && _price > _trade.openPrice) {
            isWin = true;
        } else if(!_trade.direction && _price < _trade.openPrice) {
            isWin = true;
        }
        ...
```

If trade direction is true, then the option is a *long*, otherwise its a *short*. Dissecting that further, we can observe the price of the trade is a significant factor as well.

So, if a order is a long the price currently fetched by the oracle **must be** higher than the price at the time the option was opened.

On the other hand, if its a **short**, the price **must be** lower than to consider the trade as a win. However, that's not entirely true, as the price actually **must be** lower than OR equal to the price at the time the option was created.

However, currently the function doesn't account of that, meaning it will consider such trades a loss instead of win, thereby depriving users from their rewards.

**Recommendation:**

To address this vulnerability, the code logic needs to be updated to include the equality check. The correct logic for determining a winning trade when the trade direction is short should be as follows:

```diff
+} else if(!_trade.direction && _price <= _trade.openPrice) {
   isWin = true;
}
```

**Resolution:**

[Fixed](https://github.com/Tigris-Trade/Contracts/commit/83177082dfed6d66e251605b0a54c04b9c870175)


## Medium Risk Findings (1)

### 7. No check for active Arbitrum Sequencer in getVerifiedPrice ![](https://img.shields.io/badge/-Medium-orange) ![](https://img.shields.io/badge/-Acknowledged-grey)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L362)

**Impact:**

The missing Sequencer Uptime Feed check in the `getVerifiedPrice` function potentially exposes users to inaccurate oracle data when the Arbitrum Sequencer is down, making the platform vulnerable to stale pricing attacks.

**Description:**

If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 optimistic rollup contract. You can review Chainlink docs on [L2 Sequencer Uptime Feeds](https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds/) for more details on this.

In the current implementation of the `Options.sol` contract, there is no check for the Sequencer Uptime Feed before the oracle data is returned by the `getVerifiedPrice` function. This could lead to the return of stale data, specifically when the Arbitrum Sequencer goes down.

Under such circumstances, the oracle data would not be updated, and users would continue to interact with the protocol through the L1 optimistic rollup contract. 

For instance, if a user who holds tokens worth 1 ETH each initiates a trade, and the sequencer goes down before the trade's expiry blockstamp, the oracle would return stale price data. If the token's price were to drop to 0.5 ETH while the sequencer is down, the bot wouldn't be able to liquidate the user's trade due to the stale price data, thereby exposing the platform to potential losses.

However, given that the chainlink feed can be turned off, this doesn't qualify for more than a medium.

**Recommendation:**

Adapt the following check from Chainlink's documentation:

```solidity
(
            /*uint80 roundID*/,
            int256 answer,
            uint256 startedAt,
            /*uint256 updatedAt*/,
            /*uint80 answeredInRound*/
        ) = sequencerUptimeFeed.latestRoundData();

        // Answer == 0: Sequencer is up
        // Answer == 1: Sequencer is down
        bool isSequencerUp = answer == 0;
        if (!isSequencerUp) {
            revert SequencerDown();
        }

        // Make sure the grace period has passed after the sequencer is back up.
        uint256 timeSinceUp = block.timestamp - startedAt;
        if (timeSinceUp <= GRACE_PERIOD_TIME) {
            revert GracePeriodNotOver();
        }
```


## Minor Risk Findings(2)

### 8. Missing asset existence check ![](https://img.shields.io/badge/-Minor-yellow) ![](https://img.shields.io/badge/-Acknowledged-grey)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L548-L559)

**Impact**

The `setTradedAsset` function allows adding assets to the system by setting various parameters for the asset. However, it lacks a check to verify whether an asset with the same ID already exists. As a result, if an asset with the same ID is passed to this function, the existing asset will be overwritten with the new values, regardless of whether it was intentional or not.

```solidity
    function setTradedAsset(
        uint _id,
        uint _maxC,
        uint _minC,
        uint _maxD,
        uint _minD,
        uint _maxO,
        uint _winP,
        uint[] calldata _fees
    ) external onlyOwner {
        require(_maxC > _minC, "!C");
        require(_maxD > _minD, "!D");

        TradedAsset storage _asset = tradedAssets[_id];

        _asset.maxCollateral = _maxC;
        _asset.minCollateral = _minC;
        _asset.maxDuration = _maxD;
        _asset.minDuration = _minD;
        _asset.maxOpen = _maxO;
        _asset.assetId = _id;
        _asset.winPercent = _winP;
        _asset.closeFee = _fees[0];
        _asset.botFee = _fees[1];
        _asset.refFee = _fees[2];
    }
```

**Recommendation**

It is recommended to add a check in the `setTradedAsset` function to ensure that an asset with the same ID doesn't already exist in the system. Here is a modified version of the function with the added check:

```diff
function setTradedAsset(
    uint _id,
    uint _maxC,
    uint _minC,
    uint _maxD,
    uint _minD,
    uint _maxO,
    uint _winP,
    uint[] calldata _fees
) external onlyOwner {
    require(_maxC > _minC, "!C");
    require(_maxD > _minD, "!D");

+    require(tradedAssets[_id].assetId == 0, "Asset already exists");

    TradedAsset storage _asset = tradedAssets[_id];

    _asset.maxCollateral = _maxC;
    _asset.minCollateral = _minC;
    _asset.maxDuration = _maxD;
    _asset.minDuration = _minD;
    _asset.maxOpen = _maxO;
    _asset.assetId = _id;
    _asset.winPercent = _winP;
    _asset.closeFee = _fees[0];
    _asset.botFee = _fees[1];
    _asset.refFee = _fees[2];
}

```

### 9. Redundant TradeAsset variables  ![](https://img.shields.io/badge/-Minor-yellow) ![](https://img.shields.io/badge/-Acknowledged-grey)

**Context:** [Options.sol](https://github.com/Tigris-Trade/Contracts/blob/440009d18ab7c4ac1bdbc87a4381e7e41f38041a/contracts/options/Options.sol#L565-L568)

**Impact:**

The current implementation of the `setTradedAsset` function includes the assignment of `maxDuration`, `minDuration`, and `assetId` variables to values, but these variables are unused in the rest of the code. This redundancy may lead to confusion and unnecessary storage consumption.

**Description:**

Within the `setTradedAsset` function, the following lines assign values to the variables `maxDuration`, `minDuration`, and `assetId`:

```solidity
        _asset.maxDuration = _maxD;
        _asset.minDuration = _minD;
        _asset.assetId = _id;
```

However, these variables are not referenced or utilized anywhere else within the function or the surrounding code. As a result, these assignments are redundant and do not serve any purpose in the current implementation.

**Recommendation:**

If that's the intended behavior, it is recommended to remove the unused assignments of `maxDuration`, `minDuration`, and `assetId` from the `setTradedAsset` function.
