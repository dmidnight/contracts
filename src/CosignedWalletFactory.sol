// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/proxy/Clones.sol";

interface ICosignedWallet {
    function initialize(address token, address owner, address cosigner, uint256 minTimeToBypassCosigner) external;
}

contract CosignedWalletFactory {
    using Clones for address;

    address public immutable _implementation;
    address public immutable _cosigner;

    string constant CONTRACT_ERROR = "Not a contract";
    string constant ADDRESS_ERROR = "Bad address";

    event WalletCreated(address indexed wallet, address indexed token, address indexed owner);

    constructor(address implementation, address cosigner) {
        require(implementation != address(0), ADDRESS_ERROR);
        require(cosigner != address(0), ADDRESS_ERROR);

        // verify token address is a contract
        bool addressIsContract = isContract(implementation);
        require(addressIsContract, CONTRACT_ERROR);

        _implementation = implementation;
        _cosigner = cosigner;
    }

    function createWallet(address token, address signer, uint256 minTimeToBypassCosigner) external returns (address) {
        require(signer != address(0), ADDRESS_ERROR);

        if (token != address(0)) {
            // verify token address is a contract
            bool addressIsContract = isContract(token);
            require(addressIsContract, CONTRACT_ERROR);
            // verify token address is not the implementation address
            require(token != _implementation, ADDRESS_ERROR);
            // verify token address is not the factory address
            require(token != address(this), ADDRESS_ERROR);
        }

        bytes32 salt = keccak256(abi.encodePacked(token, signer, _cosigner, minTimeToBypassCosigner));
        address clone = _implementation.cloneDeterministic(salt);

        ICosignedWallet(clone).initialize(token, signer, _cosigner, minTimeToBypassCosigner);

        emit WalletCreated(clone, token, signer);

        return clone;
    }

    function predictWalletAddress(address token, address signer, uint256 minTimeToBypassCosigner)
        external
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(token, signer, _cosigner, minTimeToBypassCosigner));
        return _implementation.predictDeterministicAddress(salt, address(this));
    }

    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}
