//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

interface IPlonkVerifier {
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInput
    ) external view returns(bool);
}