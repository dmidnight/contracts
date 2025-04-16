// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {CosignedWallet} from "../src/CosignedWallet.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract CosignedWalletTest is Test {
    using ECDSA for bytes32;

    CosignedWallet public tokenWallet;
    CosignedWallet public ethWallet;

    TestToken public token;

    uint256 privateKeySigner;
    uint256 privateKeyCosigner;

    address public signer;
    address public cosigner;

    event Refund(uint256 amount, uint256 indexed nonce);

    function setUp() public {
        // Setup private keys for signer and cosigner
        privateKeySigner = 0x1;
        privateKeyCosigner = 0x2;

        signer = vm.addr(privateKeySigner);
        cosigner = vm.addr(privateKeyCosigner);

        token = new TestToken("Test Token", "TT");
        token.mint(signer, 100 * 10 ** 18);

        vm.deal(signer, 100 * 10 ** 18);

        // Deploy the CosignedWallet contract
        tokenWallet = new CosignedWallet();
        tokenWallet.initialize(address(token), signer, cosigner, 45 days);

        // Transfer tokens to the wallet
        vm.startPrank(signer);
        token.transfer(address(tokenWallet), 100 * 10 ** 18);
        vm.stopPrank();

        ethWallet = new CosignedWallet();
        ethWallet.initialize(address(0), signer, cosigner, 45 days);

        // Transfer ETH to the wallet
        vm.startPrank(signer);
        (bool success,) = address(ethWallet).call{value: 100 * 10 ** 18}("");
        require(success, "Failed to transfer ETH");
        vm.stopPrank();
    }

    function test_settle_ETH() public {
        uint256 settlementAmount = 10 * 10 ** 18;
        uint256 nonce = 0x1;
        uint256 fee = 10 ** 16; // 0.01 ETH

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ethWallet.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        ethWallet.TRANSFER_TYPEHASH(), cosigner, settlementAmount, nonce, fee, block.timestamp + 1
                    )
                )
            )
        );

        // Sign the message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeySigner, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Check the balance of the wallet before settlement
        uint256 walletBalance = address(ethWallet).balance;
        assertEq(walletBalance, 100 * 10 ** 18, "Wallet balance should be 100 tokens before settlement");

        // Settle an offchain signed payment
        vm.startPrank(cosigner);
        ethWallet.transfer(cosigner, settlementAmount, nonce, fee, block.timestamp + 1, 0, signature);
        vm.stopPrank();

        // Check the balance of the wallet after settlement
        uint256 walletBalanceAfter = address(ethWallet).balance;
        assertEq(walletBalanceAfter, 90 * 10 ** 18 - fee, "Wallet balance should be 90 tokens - fee after settlement");
        // Check the balance of the cosigner after settlement
        uint256 cosignerBalance = address(cosigner).balance;
        assertEq(cosignerBalance, 10 * 10 ** 18 + fee, "Cosigner balance should be 10 tokens + fee after settlement");
    }

    function test_settle_ERC20() public {
        uint256 settlementAmount = 10 * 10 ** 18;
        uint256 nonce = 0x1;
        uint256 fee = 10 ** 16; // 0.01 ETH

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                tokenWallet.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        tokenWallet.TRANSFER_TYPEHASH(), cosigner, settlementAmount, nonce, fee, block.timestamp + 1
                    )
                )
            )
        );

        // Sign the message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeySigner, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Settle an offchain signed payment
        vm.startPrank(cosigner);
        tokenWallet.transfer(cosigner, settlementAmount, nonce, fee, block.timestamp + 1, 0, signature);
        vm.stopPrank();

        // Check the balance of the wallet after settlement
        uint256 walletBalance = token.balanceOf(address(tokenWallet));
        assertEq(walletBalance, 90 * 10 ** 18 - fee, "Wallet balance should be 90 tokens - fee after settlement");
        // Check the balance of the cosigner after settlement
        uint256 cosignerBalance = token.balanceOf(cosigner);
        assertEq(cosignerBalance, 10 * 10 ** 18 + fee, "Cosigner balance should be 10 tokens + fee after settlement");
    }

    function test_withdrawUnsettledBalance_ERC20() public {
        // Go forward 45 days
        vm.warp(block.timestamp + 45 days);
        console.log("Current block number:", block.number);
        console.log("Current block timestamp:", block.timestamp);

        // Withdraw the unsettled balance
        vm.startPrank(signer);
        tokenWallet.withdrawUnsettledBalance(signer);
        vm.stopPrank();

        // Check the balance of the wallet after withdrawal
        uint256 walletBalance = token.balanceOf(address(tokenWallet));
        assertEq(walletBalance, 0, "Wallet balance should be 0 tokens after withdrawal");

        // Check the balance of the signer after withdrawal
        uint256 signerBalance = token.balanceOf(signer);
        assertEq(signerBalance, 100 * 10 ** 18, "Signer balance should be 100 tokens after withdrawal");
    }

    function test_verifySignature() public view {
        uint256 settlementAmount = 10 * 10 ** 18;
        uint256 nonce = 0x1;
        uint256 fee = 10 ** 16; // 0.01 ETH

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                tokenWallet.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        tokenWallet.TRANSFER_TYPEHASH(), cosigner, settlementAmount, nonce, fee, block.timestamp + 1
                    )
                )
            )
        );

        // Sign the message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeySigner, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify the signature
        bool isValid =
            tokenWallet.verifySignature(cosigner, settlementAmount, nonce, fee, block.timestamp + 1, signature);
        assertTrue(isValid, "Signature should be valid");
    }

    function test_withdrawInvalidToken_ERC20() public {
        TestToken token2 = new TestToken("Test Token 2", "TT2");
        token2.mint(signer, 100 * 10 ** 18);

        // Transfer tokens to the wallet
        vm.startPrank(signer);
        token2.transfer(address(tokenWallet), 100 * 10 ** 18);
        vm.stopPrank();

        // Withdraw the invalid token
        vm.startPrank(signer);
        tokenWallet.withdrawInvalidToken(address(token2), signer);
        vm.stopPrank();

        uint256 token2Balance = token2.balanceOf(signer);
        assertEq(token2Balance, 100 * 10 ** 18, "Signer should have 100 tokens after withdrawal");

        // Check the balance of the wallet after withdrawal
        uint256 walletBalance = token2.balanceOf(address(tokenWallet));
        assertEq(walletBalance, 0, "Wallet balance should be 0 tokens after withdrawal");
    }

    function test_withdrawInvalidToken_ETH() public {
        vm.deal(signer, 100 * 10 ** 18);

        // Transfer ETH to the wallet
        vm.startPrank(signer);
        (bool success,) = address(tokenWallet).call{value: 100 * 10 ** 18}("");
        require(success, "Failed to transfer ETH");
        vm.stopPrank();

        // Withdraw the invalid token
        vm.startPrank(signer);
        tokenWallet.withdrawInvalidToken(address(0), signer);
        vm.stopPrank();

        uint256 signerBalance = address(signer).balance;
        assertEq(signerBalance, 100 * 10 ** 18, "Signer should have 100 tokens after withdrawal");

        // Check the balance of the wallet after withdrawal
        uint256 walletBalance = address(tokenWallet).balance;
        assertEq(walletBalance, 0, "Wallet balance should be 0 tokens after withdrawal");
    }

    function test_refundERC20() public {
        // create a payment to refund
        uint256 settlementAmount = 10 * 10 ** 18;
        uint256 nonce = 0x1;
        uint256 fee = 10 ** 16; // 0.01 ETH

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                tokenWallet.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        tokenWallet.TRANSFER_TYPEHASH(), cosigner, settlementAmount, nonce, fee, block.timestamp + 1
                    )
                )
            )
        );
        // Sign the message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeySigner, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Settle an offchain signed payment
        vm.startPrank(cosigner);
        tokenWallet.transfer(cosigner, settlementAmount, nonce, fee, block.timestamp + 1, 0, signature);
        vm.stopPrank();

        // Check the balance of the wallet after settlement
        uint256 walletBalance = token.balanceOf(address(tokenWallet));
        assertEq(walletBalance, 90 * 10 ** 18 - fee, "Wallet balance should be 90 tokens - fee after settlement");

        // Check the balance of the cosigner after settlement
        uint256 cosignerBalance = token.balanceOf(cosigner);
        assertEq(cosignerBalance, 10 * 10 ** 18 + fee, "Cosigner balance should be 10 tokens after settlement");

        // Refund the payment
        vm.startPrank(cosigner);
        token.approve(address(tokenWallet), settlementAmount);

        vm.expectEmit(true, true, false, false);
        emit Refund(settlementAmount, nonce);

        tokenWallet.refundERC20(settlementAmount, nonce, cosigner);
        vm.stopPrank();

        // Check the balance of the wallet after refund
        uint256 walletBalanceAfter = token.balanceOf(address(tokenWallet));
        assertEq(walletBalanceAfter, 100 * 10 ** 18 - fee, "Wallet balance should be 100 tokens - fee after refund");

        // Check the balance of the cosigner after refund
        uint256 cosignerBalanceAfter = token.balanceOf(cosigner);
        assertEq(cosignerBalanceAfter, fee, "Cosigner balance should be 0 tokens + fee after refund");
    }

    function test_refundGasToken() public {
        // create a payment to refund
        uint256 settlementAmount = 10 * 10 ** 18;
        uint256 nonce = 0x1;
        uint256 fee = 10 ** 16; // 0.01 ETH

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ethWallet.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        ethWallet.TRANSFER_TYPEHASH(), cosigner, settlementAmount, nonce, fee, block.timestamp + 1
                    )
                )
            )
        );
        // Sign the message hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeySigner, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Settle an offchain signed payment
        vm.startPrank(cosigner);
        ethWallet.transfer(cosigner, settlementAmount, nonce, fee, block.timestamp + 1, 0, signature);
        vm.stopPrank();

        // Check the balance of the wallet after settlement
        uint256 walletBalance = address(ethWallet).balance;
        assertEq(walletBalance, 90 * 10 ** 18 - fee, "Wallet balance should be 90 tokens - fee after settlement");

        // Check the balance of the cosigner after settlement
        uint256 cosignerBalance = address(cosigner).balance;
        assertEq(cosignerBalance, 10 * 10 ** 18 + fee, "Cosigner balance should be 10 tokens + fee after settlement");

        // Refund the payment
        vm.startPrank(cosigner);

        vm.expectEmit(true, true, false, false);
        emit Refund(settlementAmount, nonce);

        ethWallet.refundGasToken{value: settlementAmount}(nonce);
        vm.stopPrank();

        // Check the balance of the wallet after refund
        uint256 walletBalanceAfter = address(ethWallet).balance;
        assertEq(walletBalanceAfter, 100 * 10 ** 18 - fee, "Wallet balance should be 100 tokens after refund");

        // Check the balance of the cosigner after refund
        uint256 cosignerBalanceAfter = address(cosigner).balance;
        assertEq(cosignerBalanceAfter, fee, "Cosigner balance should be 0 tokens + fee after refund");
    }

    function test_getBalance() public view {
        // Check the balance of the wallet
        uint256 walletBalance = tokenWallet.getBalance();
        assertEq(walletBalance, 100 * 10 ** 18, "Wallet balance should be 100 tokens");

        // Check the balance of the wallet
        uint256 ethWalletBalance = ethWallet.getBalance();
        assertEq(ethWalletBalance, 100 * 10 ** 18, "Wallet balance should be 100 tokens");
    }
}
