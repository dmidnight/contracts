// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";

import {CosignedWallet} from "../src/CosignedWallet.sol";
import {CosignedWalletFactory} from "../src/CosignedWalletFactory.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
}

contract CossignedWalletFactoryTest is Test {
    CosignedWalletFactory factory;

    CosignedWallet public wallet;
    TestToken public token;

    uint256 privateKeySigner;
    uint256 privateKeyCosigner;

    address public signer;
    address public cosigner;

    address public implementation;

    function setUp() public {
        // Setup private keys for signer and cosigner
        privateKeySigner = 0x1;
        privateKeyCosigner = 0x2;

        token = new TestToken("Test Token", "TT");

        signer = vm.addr(privateKeySigner);
        cosigner = vm.addr(privateKeyCosigner);

        implementation = address(new CosignedWallet());
        factory = new CosignedWalletFactory(implementation, cosigner);
    }

    function test_createWallet_and_predictWalletAddress() public {
        // Create a new instance
        address newWalletAddress = factory.createWallet(address(token), signer, 45 days);

        // Verify that the contract was deployed
        assertEq(newWalletAddress, address(factory.predictWalletAddress(address(token), signer, 45 days)));
    }

    function test_cloneCanReceiveETHBeforeDeployment() public {
        address predictedAddress = factory.predictWalletAddress(address(token), signer, 45 days);
        vm.deal(predictedAddress, 1 ether);

        vm.startPrank(predictedAddress);
        (bool success,) = predictedAddress.call{value: 1 ether}("");
        vm.stopPrank();

        assertTrue(success, "Failed to send ether to the predicted address");
        assertEq(address(predictedAddress).balance, 1 ether, "Predicted address should have 1 ether");
    }
}
