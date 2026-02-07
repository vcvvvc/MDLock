---
title: "Proxy_Solidity"
date: 2023-08-22T18:07:06+08:00
tags: [BlockChain, Ethereum, Smart Contract, Solidity]
draft: false
---

可升级智能合约

Proxy 是一种智能合约的设计模式，它可以实现合约的可升级性。Proxy 合约是一个简单的合约，它只负责将收到的调用请求转发给另一个逻辑合约，而不执行任何自己的逻辑。这样，当需要升级合约时，只需要部署一个新的逻辑合约，并在 Proxy 合约中更新其地址，就可以保持 Proxy 合约的地址不变，同时使用新的逻辑。Proxy 合约通常使用 delegatecall 操作码来实现调用转发，这样可以保留 Proxy 合约的存储和上下文，而执行逻辑合约的代码。

