//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

interface IAccountProxy {
    function initProxy(
        address logic,
        bytes calldata data
    ) external;
}