# Solidity Contracts

A collection of Solidity contracts

## Cosigned Wallet

Contract and factory for a Cosigned Wallet - onchain settlement of an offline ERC20 or gas token commitment.

- This contract allows a cosigner to accept offchain signed payment commitments
- Payment commitments contain an expiration date
- Contract provides a failsafe incase cosigner becomes inactive (using \_minTimeToBypassCosigner)
- Signer should create at least one transfer within the timeframe or the Cosigner should not accept any new payment commitments
- Signer can create a payment to cosigner to keep wallet active
- Cosigner can require a fee to process transfers without gas
- Cosigner can make change for preauthorized payments back to the contract

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
