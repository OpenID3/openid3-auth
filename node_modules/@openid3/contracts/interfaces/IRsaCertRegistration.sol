//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

interface IRsaCertRegistration {
    function getCert(bytes32 kidHash) external view returns (address);
}