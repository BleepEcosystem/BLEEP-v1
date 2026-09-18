// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title BleepSepoliaFulfill
/// @notice Native Sepolia relay contract for BLEEP Connect executor deliveries.
/// @dev This contract enforces chain ID, replay protection, expiry, and safe ETH transfer.
contract BleepFulfill {
    /// Chain ID for Sepolia.
    uint256 public constant SEPOLIA_CHAIN_ID = 11155111;

    /// The deployer can perform emergency recovery if necessary.
    address public immutable owner;

    /// Prevent duplicate intent fulfillment.
    mapping(bytes32 => bool) public fulfilled;

    event IntentFulfilled(
        bytes32 indexed intentId,
        address indexed recipient,
        uint256 amount,
        uint256 deadline,
        uint256 timestamp
    );

    event EmergencyWithdraw(address indexed owner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "BleepFulfill: caller is not the owner");
        _;
    }

    modifier onlySepolia() {
        require(block.chainid == SEPOLIA_CHAIN_ID, "BleepFulfill: wrong chain");
        _;
    }

    constructor() onlySepolia {
        owner = msg.sender;
    }

    /// @notice Fulfill an intent by transferring received ETH to the recipient.
    /// @param intentId Unique identifier of the cross-chain transfer intent.
    /// @param recipient Destination address on Sepolia.
    /// @param minAmount Minimum amount that must be delivered to the recipient.
    /// @param deadline Unix timestamp after which the relay is invalid.
    function fulfillIntent(
        bytes32 intentId,
        address recipient,
        uint256 minAmount,
        uint256 deadline
    ) external payable onlyOwner onlySepolia {
        require(recipient != address(0), "BleepFulfill: invalid recipient");
        require(!fulfilled[intentId], "BleepFulfill: intent already filled");
        require(msg.value >= minAmount, "BleepFulfill: amount below minimum");
        // forge-lint: disable-next-line(block-timestamp)
        require(deadline == 0 || block.timestamp <= deadline, "BleepFulfill: deadline passed");

        fulfilled[intentId] = true;
        emit IntentFulfilled(intentId, recipient, msg.value, deadline, block.timestamp);

        (bool success, ) = recipient.call{value: msg.value}("");
        require(success, "BleepFulfill: transfer failed");
    }

    /// @notice Recover any accidentally sent ETH held in the contract.
    function emergencyWithdraw() external onlyOwner onlySepolia {
        uint256 balance = address(this).balance;
        require(balance > 0, "BleepFulfill: no balance to withdraw");
        emit EmergencyWithdraw(owner, balance);
        (bool success, ) = owner.call{value: balance}("");
        require(success, "BleepFulfill: withdraw failed");
    }

    receive() external payable {
        revert("BleepFulfill: direct deposits forbidden");
    }

    fallback() external payable {
        revert("BleepFulfill: direct calls forbidden");
    }
}
