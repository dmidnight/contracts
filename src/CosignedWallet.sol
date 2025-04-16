// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract CosignedWallet is Initializable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant TRANSFER_TYPEHASH =
        keccak256("Transfer(address to,uint256 amount,uint256 nonce,uint256 fee,uint256 expires)");

    uint256 public _minTimeToBypassCosigner;
    uint256 public _updatedDate;

    address public _tokenAddress;
    address public _signer;
    address public _cosigner;

    string constant CANNOT_REFUND_ERROR = "Cannot refund";
    string constant NONCE_ERROR = "Already spent";
    string constant SIG_ERROR = "Invalid signature";
    string constant WRONG_TOKEN_ERROR = "Wrong token";

    mapping(uint256 => bool) public _spentNonces;

    event Refund(uint256 indexed nonce, uint256 amount);
    event Transfer(address indexed to, uint256 indexed nonce, uint256 amount, uint256 fee, uint256 unspent);
    event Withdrawal(address indexed tokenAddress, address indexed to, uint256 amount);

    function initialize(address tokenAddress, address signer, address cosigner, uint256 minTimeToBypassCosigner)
        public
        initializer
    {
        _tokenAddress = tokenAddress;
        _minTimeToBypassCosigner = minTimeToBypassCosigner;
        _signer = signer;
        _cosigner = cosigner;

        _updatedDate = block.timestamp;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Cosigned Wallet"),
                keccak256("1.0.0"),
                block.chainid,
                address(this)
            )
        );
    }

    modifier onlySigner() {
        require(msg.sender == _signer, "Not signer");
        _;
    }

    modifier onlyCosigner() {
        require(msg.sender == _cosigner, "Not cosigner");
        _;
    }

    // @notice Will receive any gas tokens sent to the contract
    receive() external payable {
        // This contract address can receive gas tokens before it is deployed.
        // This function is provided to allow the same behavior after deployment
    }

    /**
     * Refund a payment using gas token
     *
     * @param nonce           A nonce to reference
     */
    function refundGasToken(uint256 nonce) public payable onlyCosigner {
        require(_tokenAddress == address(0), WRONG_TOKEN_ERROR);
        require(_spentNonces[nonce], CANNOT_REFUND_ERROR);

        _updatedDate = block.timestamp;

        // Amount is received in msg.value

        emit Refund(nonce, msg.value);
    }

    /**
     * Refund a payment - requires source to approve the transfer
     *
     * @param amount          The amount to refund
     * @param nonce           A nonce to reference
     * @param source          The address to send funds from
     */
    function refundERC20(uint256 amount, uint256 nonce, address source) public onlyCosigner {
        require(_tokenAddress != address(0), WRONG_TOKEN_ERROR);
        require(_spentNonces[nonce], CANNOT_REFUND_ERROR);
        require(source != address(this), "Bad source address");

        _updatedDate = block.timestamp;

        IERC20 token = IERC20(_tokenAddress);
        token.safeTransferFrom(source, address(this), amount);

        emit Refund(nonce, amount);
    }

    /**
     * Withdraw a token that was sent incorrectly
     *
     * @param tokenAddress            The token address
     * @param withdrawalAddress       The withdrawal address
     */
    function withdrawInvalidToken(address tokenAddress, address withdrawalAddress) public onlySigner {
        require(tokenAddress != _tokenAddress, "Token not invalid");
        require(withdrawalAddress != address(0), "Bad withdrawal address");

        uint256 balance = getBalance();

        _send(tokenAddress, withdrawalAddress, balance);

        emit Withdrawal(tokenAddress, withdrawalAddress, balance);
    }

    /**
     * Use a signed message to reduce the balance of the token, settling an offchain signed payment
     *
     * @param to     The address to send settled funds to
     * @param amount          The balance to pay
     * @param nonce           A nonce
     * @param fee             The fee to pay to the cosigner
     * @param expires         The expiration date of the transfer
     * @param unspent         The unspent amount - allows the cosigner to make change for a preauthorized payment
     * @param signature       The signed message
     */
    function transfer(
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 fee,
        uint256 expires,
        uint256 unspent,
        bytes calldata signature
    ) public onlyCosigner {
        require(!_spentNonces[nonce], NONCE_ERROR);
        require(unspent < amount, "Unspent >= amount");
        require(block.timestamp < expires, "Expired");

        require(verifySignature(to, amount, nonce, fee, expires, signature), SIG_ERROR);

        _updatedDate = block.timestamp;
        _spentNonces[nonce] = true;

        uint256 sendAmount = amount - unspent;

        if (fee > 0) {
            require(getBalance() >= sendAmount + fee, "Not enough for fee");
            _send(_tokenAddress, _cosigner, fee);
        }

        _send(_tokenAddress, to, sendAmount);

        emit Transfer(to, nonce, sendAmount, fee, unspent);
    }

    /**
     * Use a signed message to withdraw the unsettled balance after _minTimeToBypassCosigner if the cosigner is not responsive
     *
     * @param to              The withdrawal address
     */
    function withdrawUnsettledBalance(address to) public onlySigner {
        require(block.timestamp >= _updatedDate + _minTimeToBypassCosigner, "Not allowed yet");

        _updatedDate = block.timestamp;

        uint256 balance = getBalance();
        _send(_tokenAddress, to, balance);

        emit Withdrawal(_tokenAddress, to, balance);
    }

    /**
     * Verify EIP-712 signature for transfer
     *
     * @param amount      The balance to pay
     * @param nonce       A nonce
     * @param signature   The signed message
     * @return          True if the signature is valid
     */
    function verifySignature(
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 fee,
        uint256 expires,
        bytes calldata signature
    ) public view returns (bool) {
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, to, amount, nonce, fee, expires));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ECDSA.recover(digest, signature);
        return recovered == _signer;
    }

    /**
     * Get the balance of the wallet
     *
     * @return          The balance of the wallet
     */
    function getBalance() public view returns (uint256) {
        if (_tokenAddress == address(0)) {
            return address(this).balance;
        } else {
            IERC20 token = IERC20(_tokenAddress);
            return token.balanceOf(address(this));
        }
    }

    /**
     * Transfer tokens to an address from the wallet's contract
     *
     * @param tokenAddress The address of the token to send (0x for gas token)
     * @param to          The address of the beneficiary of the funds
     * @param amount      The value of the transfer (No transfer will be made if zero)
     */
    function _send(address tokenAddress, address to, uint256 amount) internal {
        if (tokenAddress == address(0)) {
            // send gas token
            address payable dest = payable(to);
            (bool success,) = dest.call{value: amount}("");
            require(success, "Send error");
        } else {
            IERC20 token = IERC20(tokenAddress);
            token.safeTransfer(to, amount);
        }
    }
}
