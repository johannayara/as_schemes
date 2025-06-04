// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title TimedMultisigWallet
/// @notice 2-of-2 Multisig with fallback to Alice after timeout
contract TimedMultisigWallet {
    address public alice;
    address public bob;
    uint256 public unlockTime; // timeout after which Alice can retrieve her coins
    bool public spent; //prevent multiple withdrawals


    /// Initalizes the contract with provided values, 
    /// allows the contract to recieve ETH during deployment
    constructor(address _alice, address _bob, uint256 _unlockTime) payable {
        alice = _alice;
        bob = _bob;
        unlockTime = _unlockTime;
    }

    /// Defines a modifier that checks if the funds have already been spent.
    modifier notSpent() {
        require(!spent, "Funds already withdrawn");
        _;
    }

    /// @notice Withdraw by both signatures (Alice and Bob), before timeout
    function multisigWithdraw(
        bytes32 messageHash,
        bytes memory sigAlice,
        bytes memory sigBob
    ) external notSpent {
        require(block.timestamp < unlockTime, "Too late for multisig");
        // Check that caller is either Alice or Bob
        require(msg.sender == alice || msg.sender == bob, "Not an authorized participant");

        address recoveredAlice = recoverSigner(messageHash, sigAlice);
        address recoveredBob = recoverSigner(messageHash, sigBob);

        // Ensure that the recovered addresses match the stored ones
        require(
            (recoveredAlice == alice && recoveredBob == bob) ||
            (recoveredAlice == bob && recoveredBob == alice),
            "Invalid signatures"
        );

        spent = true;
        payable(msg.sender).transfer(address(this).balance);
    }

    /// @notice Fallback for Alice after timeout
    function withdrawAfterTimeout() external notSpent {
        require(block.timestamp >= unlockTime, "Too early");
        require(msg.sender == alice, "Only Alice can withdraw");

        spent = true;
        payable(alice).transfer(address(this).balance);
    }

    /// signature methods.
    function splitSignature(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65);

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(sig, 32))
            // second 32 bytes.
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid sig length");

        
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

        // Add Ethereum Signed Message prefix
        bytes32 ethSignedMessageHash = prefixed(messageHash);
        // Use ecrecover to retrieve signing address
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }

    receive() external payable {}
}
