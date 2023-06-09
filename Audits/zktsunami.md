
# Audit Report - ZKTsunami

|             |                                                      |
| ----------- | ---------------------------------------------------- |
| **Date**    | May 2023                                              |
| **Auditor** | bytes032 ([@bytes032](https://twitter.com/bytes032)) |
| **Website** | https://bytes032.xyz/                                |

# About ZKTsunami

ZKTsunami is a ZKSnark who claims to provide ZK-ANONSNARK powered transactional anonymity at your fingertips. Zcash was the first to implement and apply ZK-SNARK in the decentralized cryptocurrency. The relatively costly proof generation further reduces the likelihood of its adoption in practice. 

ZKTsunami implements and integrates the state-of-the-art setup-free zero-knowledge proof protocol to enable trustless anonymous payment for smart contract platforms.

Their proposed ZK-AnonSNARK scheme also attains the optimal balance between performance and security, i.e., almost constant proof size and efficient proof generation and verification.


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

The review focused on the following commit hash [`hash`](https://github.com/Uno-Re/unore-zkt-audit/commit/eb265362ad33c28d2269176e97e0373824a21fba)
The following contracts were in scope of the audit:

|File|nSLOC|
|-------|-------|
|TransferVerifier.sol|346|
|ZKTBase.sol|273|
|Tsunami.sol|233|
|InnerProductVerifier.sol|201|
|Utils.sol|157|
|BurnVerifier.sol|135|
|ZKTLog.sol|62|
|CheckZKT.sol|44|
|ZKTERC20.sol|42|
|ZKTBank.sol|36|
|ZKTETH.sol|36|
|ZKTFactory.sol|35|
|Migrations.sol|18|
|TestERC20Token.sol|6|
|--------|--------|
|Total|1624|

NSLOC stands for 'Normalized Source Code', which is a custom measurement I use (among others) when evaluating the complexity of a codebase.

To get the NSLOC count of a file I do the following:
1.  For all functions, reduce any multiline function declarations to a single line.
2.  Remove all comments
3.  Remove all empty lines
4.  Count the remaining lines

# Summary

The audited contracts contain **1 critical** issues, **1 high severity** and **2 minor severity** issues.

| #   |                                                                Title                                                                |                                                                                           Severity                                                                                            | Status                                                                                                                                                                                                  |
| --- |:-----------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 | Inconsistency in ZKT existence check can lead to overwritting existing ZKT's | ![](https://img.shields.io/badge/-Medium-orange) | ![](https://img.shields.io/badge/-Resolved-brightgreen) | 
| 2 | Absence of 'toTokenAmount' function hinders usability of ZKETH fund(...)  | ![](https://img.shields.io/badge/-Medium-orange) | ![](https://img.shields.io/badge/-Resolved-brightgreen)  | 
| 3 | Unaddressed function renaming in Utils.sol breaks all the contracts that depend on it   | ![](https://img.shields.io/badge/-Minor-yellow) | ![](https://img.shields.io/badge/-Resolved-brightgreen) |
| 4 | Misalignment of variable names in the register() function   | ![](https://img.shields.io/badge/-Minor-yellow) | ![](https://img.shields.io/badge/-Resolved-brightgreen) |

# Findings

## Medum Risk Findings (2)

### 1. Inconsistency in ZKT existence check can lead to overwritting existing ZKT's  ![](https://img.shields.io/badge/-Medium-orange)

**Context:** [Tsunami.sol](https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/Tsunami.sol#L78-L93)

**Impact:**

This issue is of critical severity, because it allows admins to replace already existing ZKT's in the Tsunami contract, thereby potentially causing serious disruption and violating the integrity of the protocol.

**Description:**

Within the Tsunami.sol smart contract, there is an inconsistency in how ZKT existence is checked and set. Specifically, the `addZKT` function checks if the uint256 representation of `keccak256(abi.encode(symbol))` exists, but then sets it as `uint256(bytes32(bytes(symbol))`.

The problem arises from the inequality of `uint256(keccak256(abi.encode(symbol)))` and `uint256(bytes32(bytes(symbol)))`. As a result, the existence check will always fail.

This issue is present in the following code block:

```solidity
 function addZKT(string calldata symbol, address token_contract_address) public onlyAdmin {
        bytes32 zktHash = keccak256(abi.encode(symbol));
        uint256 zktId = uint256(zktHash);

        bool zktExists = zkts.contains(zktId);
        if (zktExists) {
            revert("ZKT already exists for this token.");
        }

        address erc20 = erc20Factory.newZKTERC20(address(this), token_contract_address);
        zkts.set(uint256(bytes32(bytes(symbol))), erc20);
        ZKTBase(erc20).setUnit(10000000000000000);
        ZKTBase(erc20).setAgency(payable(msg.sender));
        ZKTBase(erc20).setAdmin(msg.sender);
    }
```

**Recommendation:**

To rectify this critical issue, it is suggested to use the same `uint256(bytes32(bytes(symbol)))` for both the existence check and the set operation. This consistency will ensure accurate ZKT existence verification.

```diff
 function addZKT(string calldata symbol, address token_contract_address) public onlyAdmin {
+        uint256 zktId = uint256(bytes32(bytes(symbol))

        bool zktExists = zkts.contains(zktId);
        if (zktExists) {
            revert("ZKT already exists for this token.");
        }

        address erc20 = erc20Factory.newZKTERC20(address(this), token_contract_address);
        zkts.set(uint256(bytes32(bytes(symbol))), erc20);
        ZKTBase(erc20).setUnit(10000000000000000);
        ZKTBase(erc20).setAgency(payable(msg.sender));
        ZKTBase(erc20).setAdmin(msg.sender);
    }
```

### 2. Absence of 'toTokenAmount' function hinders usability of ZKETH fund(...)  ![](https://img.shields.io/badge/-Medium-orange)

**Context:** [ZKETH.sol](https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/ZKTETH.sol#L14-L16)

**Impact:**

This issue renders the `fund` function in the ZKETH contract practically unusable, thus potentially preventing users from depositing native tokens.

In the ZKETH contract, the `fund` function is trying to use a function called `toTokenAmount` for the validation of the amount that is to be processed. However, upon reviewing the provided code and available functions in the codebase, it's clear that there is no such function named `toTokenAmount`.

The code snippet for the `fund` function is as follows:

```solidity
    // Fund function to deposit native tokens
    function fund(bytes32[2] calldata y, uint256 unitAmount, bytes calldata encGuess) override external payable {
        uint256 tokenAmount = toTokenAmount(msg.value);
```

In the codebase, there is a function named `toUnitAmount` present in the Utils contract, but `toTokenAmount` is nowhere to be found.

Here's the code snippet for `toUnitAmount`:

https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/ZKTBase.sol#L66-L71

```solidity
   function toUnitAmount(uint256 nativeAmount) internal view returns (uint256) {
        require(nativeAmount % bank.unit == 0, "error: invalid nativeAmount.");
        uint256 amount = nativeAmount / bank.unit;
        require(0 <= amount && amount <= bank.MAX, "toUnitAmount: out of range."); 
        return amount;
    }
```

This practically means the `fund` function is unuseable as is.

**Recommendation:**

To rectify this issue, it's recommended to replace the non-existent `toTokenAmount` with `toUnitAmount` in the `fund` function, assuming `toUnitAmount` provides the necessary functionality required by `fund`. This will ensure that the `fund` function will perform as intended.

## Minor Risk Findings(2)

### 3. Unaddressed function renaming in Utils.sol breaks all the contracts that depend on it  ![](https://img.shields.io/badge/-Minor-yellow)

**Context:** [TransferVerifier.sol](https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/TransferVerifier.sol#L208), [BurnVerifier.sol](https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/BurnVerifier.sol#L118), [InnerProductVerifier.sol](https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/InnerProductVerifier.sol#L207-L212)

**Impact:**

This issue renders any contract that relies on Utils.sol unusable. The renaming of key functions in Utils.sol without accounting for these changes throughout the rest of the codebase has resulted in a breakdown of the contract execution and interdependencies.

**Description**

The Utils.sol contract is a heavily modified version of the Suterusu Utils.sol contract. A range of functions have been renamed in the ZKT's implementation:

1.  pAdd -> pointAdd
2.  pMul -> pointMul
3.  pNeg -> pointNeg
4.  pEqual -> pointEqual
5.  g -> generator
6.  h -> cofactor
7.  mapInto -> mapToCurve
8.  slice -> extractSlice
9.  uint2str -> uintToString

Despite these significant changes, the rest of the codebase does not reflect the new function names. This oversight has caused a cascading effect, where contracts such as TransferVerifier.sol, BurnVerifier.sol, and InnerProductVerifier.sol, which rely on Utils.sol, cannot execute properly due to unrecognized function calls. Essentially, these contracts have been "bricked" due to the changes in Utils.sol.

**Recommendation:**

To rectify this issue, it is imperative to reflect the name changes throughout the entire codebase. Every contract that relies on Utils.sol needs to be updated to call the correctly renamed functions. This will ensure proper interaction between contracts and restore the intended functionality.

Alternatively, consider reverting the function names to their original form if the renaming is not crucial. This option would also require a thorough check of the codebase to ensure the integrity and functionality of the contracts.


### 4. **Misalignment of variable names in the register() function**  ![](https://img.shields.io/badge/-Minor-yellow)

**Context:** [Tsunami.sol](https://github.com/Uno-Re/unore-zkt-audit/blob/8c58c3063e577e8a85612e954dfb6cc93f7ac3e2/Tsunami.sol#L170-L173)

**Description:**

The register function in the smart contract begins with an attempt to create a Utils.ECPoint struct. However, there is a discrepancy in the variable names used. The function attempts to assign values to X and Y, but the ECPoint struct expects the lowercase versions x and y.

Here is the code snippet in question:

```solidity
    function register(bytes32[2] calldata y_tuple, uint256 c, uint256 s) external {
        // Calculate y
        Utils.ECPoint memory y = Utils.ECPoint({
            X: y_tuple[0],
            Y: y_tuple[1]
        });
```


In contrast, the ECPoint struct is defined as follows:

```solidity
    struct ECPoint {
        bytes32 x;
        bytes32 y;
    }
```



**Recommendation:**

To resolve this issue, the variables `X` and `Y` should be replaced with `x` and `y` in the `register` function to align with the `ECPoint` struct. This modification ensures the contract will compile and run as expected:

```diff
    function register(bytes32[2] calldata y_tuple, uint256 c, uint256 s) external {
        // Calculate y
        Utils.ECPoint memory y = Utils.ECPoint({
+            x: y_tuple[0],
+            y: y_tuple[1]
-            X: y_tuple[0],
-            Y: y_tuple[1]
        });

```
