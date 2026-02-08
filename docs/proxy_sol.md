---
title: "Proxy_Solidity"
date: 2023-08-22T18:07:06+08:00
tags: [BlockChain, Ethereum, Smart Contract, Solidity]
draft: false
---

## 可升级智能合约

Pr**oxy**

```shell
git init
```

**是一种智能合约的设计模式** 

*aaa*

### 比特币是一个状态转换系统 {#bitcoin-as-a-state-transition-system}

![以太坊状态转换](/img/eth/ethereum-state-transition.png)

从技术角度讲，诸如比特币等加密货币账本可视作一种状态转换系统，该系统有一个“状态”，由全部现存比特币的所有权状态和一个“状态转换函数”组成，状态转换函数以状态和交易为输入并输出新状态作为结果。 例如，在标准的银行系统中，状态就是一个资产负债表，一笔交易是一个从 A 帐户向 B 帐户转账$X的请求，状态转换函数将从A帐户中减去$X，向 B 帐户增加$X。 如果A帐户的余额在第一步中小于$X，状态转换函数就会返回错误提示。 所以，可以如此定义：

```
APPLY(S,TX) -> S' or ERROR
```

上面提到的银行系统中，状态转换函数如下：

```js
APPLY({ Alice: $50, Bob: $50 },"send $20 from Alice to Bob") = { Alice: $30, Bob: $70 }
```



---

# RE:
##RE:
