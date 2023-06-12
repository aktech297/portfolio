# Audit Report - xTig

|             |                                                      |
| ----------- | ---------------------------------------------------- |
| **Date**    | June 2023                                              |
| **Auditor** | bytes032 ([@bytes032](https://twitter.com/bytes032)) |
| **Website** | https://bytes032.xyz/                                |

# About Tigris Trade

Tigris is a leveraged trading platform that utilizes price data signed by oracles off-chain to provide atomic trades and real-time pair prices.

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

The review focused on the commit hash [`hash`](https://github.com/Tigris-Trade/Contracts/commit/386e86a1c7a1cfb398b269ecec28616a6c252b64)

The following contracts were in scope of the audit:

| File           | nSLOC |
| -------------- | ---- |
| xTig.sol  | 259  |
| ---      | --- |
| Total:        | 648     |


NSLOC stands for 'Normalized Source Code', which is a custom measurement I use (among others) when evaluating the complexity of a codebase.

To get the NSLOC count of a file I do the following:
1.  For all functions, reduce any multiline function declarations to a single line.
2.  Remove all comments
3.  Remove all empty lines
4.  Count the remaining lines

# Summary

The audited contracts contain **2 minor** issues:

| #   |                             Title                              |                    Severity                     | Status                                                  |
| --- |:--------------------------------------------------------------:|:-----------------------------------------------:|:------------------------------------------------------- |
| 1   | Whitelisting Reward Tokens without an unwhitelisting mechanism | ![](https://img.shields.io/badge/-Minor-yellow) |  ![](https://img.shields.io/badge/-Resolved-brightgreen)
| 2   |       Incompatibility Issue with Solidity Version 0.8.20       | ![](https://img.shields.io/badge/-Minor-yellow) | ![](https://img.shields.io/badge/-Resolved-brightgreen) |

# Findings

## Minor risk findings (1)

### 1.  Whitelisting Reward Tokens without an unwhitelisting mechanism ![](https://img.shields.io/badge/-Minor-yellow)

**Context:** [xTig.sol](https://github.com/Tigris-Trade/Contracts/blob/386e86a1c7a1cfb398b269ecec28616a6c252b64/contracts/xTIG.sol#L188-L192)

**Impact**

There's a lack of flexibility and control in managing the whitelisted tokens. This can not directly lead to financial loss and can only complicate token management in specific circumstances and create situations where unwanted tokens cannot be removed from the rewards pool.

**Description**

The whitelistReward function is used to whitelist reward tokens.

```solidity
    function whitelistReward(address _rewardToken) external onlyOwner {
        require(!rewardTokens.get(_rewardToken), "Already whitelisted");
        rewardTokens.set(_rewardToken);
        emit TokenWhitelisted(_rewardToken);
    }
```

However, the contract currently lacks a mechanism to unwhitelist tokens. This means that once a token is whitelisted, it remains so indefinitely, unless the entire contract is redeployed. 

In a scenario where the team wants to cease the use of a particular reward token, the contract offers no simple means to achieve this. Redeployment of the contract, especially when there are accrued rewards, would be potentially disruptive.

**Recommendation**

Implement an `unwhitelistReward` function in the xTIG contract that allows the removal of tokens from the whitelist. This function should only be callable by the contract owner, similar to the `whitelistReward` function. This would improve the contract's flexibility and provide better control over the token management.

The `unwhitelistReward` function could look something like this:

```solidity
    function unwhitelistReward(address _rewardToken) external onlyOwner {
        require(rewardTokens.get(_rewardToken), "Token not whitelisted");
        rewardTokens.remove(_rewardToken);
        emit TokenUnwhitelisted(_rewardToken);
    }
```


### 2.  Incompatibility Issue with Solidity Version 0.8.20  ![](https://img.shields.io/badge/-Minor-yellow)

**Context:** [xTig.sol](https://github.com/Tigris-Trade/Contracts/blob/386e86a1c7a1cfb398b269ecec28616a6c252b64/contracts/xTIG.sol#L188-L192)

**Impact**

The choice of Solidity version 0.8.20 makes the potentially deployed contract non-functional due to opcode incompatibility.

**Description**

In the xTIG contract, Solidity version 0.8.20 is used as specified in the pragma directive:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
```

However, due to an opcode incompatibility issue (`push0` opcode is not supported yet), the contract compiles but is non-functional when deployed.

This is because Solidity version 0.8.20 or higher can only be used with an EVM (Ethereum Virtual Machine) version lower than the default `shanghai`. The incompatible `push0` opcode will soon be supported, but it currently makes contracts compiled with Solidity 0.8.20 non-functional.

The compatibility issues mean that the entire contract fails to function as expected, making it impossible to perform any operations on it. The EVM version setting can be adjusted in solc as per the instructions [here](https://docs.soliditylang.org/en/v0.8.20/using-the-compiler.html#setting-the-evm-version-to-target) or in Hardhat as mentioned [here](https://hardhat.org/hardhat-runner/docs/guides/compile-contracts#configuring-the-compiler).

Versions up to and including 0.8.19 are fully compatible, meaning contracts written in these versions will not face this opcode issue.

**Recommendation**

Downgrade the Solidity version to 0.8.19 or below to avoid the opcode incompatibility issue until the `push0` opcode support is officially implemented.

Alternatively, you could change the EVM version to a lower one than the default 'shanghai' when compiling the contract