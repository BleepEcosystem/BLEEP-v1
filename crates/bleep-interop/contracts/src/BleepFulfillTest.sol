// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title BleepFulfillTest
/// @notice Test version of BleepSepoliaFulfill that works on any chain.
/// @dev This contract is for testing purposes only.
contract BleepFulfillTest {
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
        require(msg.sender == owner, "BleepFulfillTest: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Fulfill an intent by transferring received ETH to the recipient.
    /// @param intentId Unique identifier of the cross-chain transfer intent.
    /// @param recipient Destination address.
    /// @param minAmount Minimum amount that must be delivered to the recipient.
    /// @param deadline Unix timestamp after which the relay is invalid.
    function fulfillIntent(
        bytes32 intentId,
        address recipient,
        uint256 minAmount,
        uint256 deadline
    ) external payable onlyOwner {
        require(recipient != address(0), "BleepFulfillTest: invalid recipient");
        require(!fulfilled[intentId], "BleepFulfillTest: intent already filled");
        require(msg.value >= minAmount, "BleepFulfillTest: amount below minimum");
        // forge-lint: disable-next-line(block-timestamp)
        require(deadline == 0 || block.timestamp <= deadline, "BleepFulfillTest: deadline passed");

        fulfilled[intentId] = true;
        emit IntentFulfilled(intentId, recipient, msg.value, deadline, block.timestamp);

        (bool success, ) = recipient.call{value: msg.value}("");
        require(success, "BleepFulfillTest: transfer failed");
    }

    /// @notice Recover any accidentally sent ETH held in the contract.
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "BleepFulfillTest: no balance to withdraw");
        emit EmergencyWithdraw(owner, balance);
        (bool success, ) = owner.call{value: balance}("");
        require(success, "BleepFulfillTest: withdraw failed");
    }

    receive() external payable {
        revert("BleepFulfillTest: direct deposits forbidden");
    }

    fallback() external payable {
        revert("BleepFulfillTest: direct calls forbidden");
    }
}