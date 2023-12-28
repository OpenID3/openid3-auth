//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

interface IRsaCert {
    function getIssuer() external view returns (bytes32);

    function N() external view returns (bytes memory);

    function E() external view returns (bytes memory);
}