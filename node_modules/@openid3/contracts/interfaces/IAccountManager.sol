//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "./IAccountValidator.sol";

interface IAccountManager is IAccountValidator {
    struct ValidationData {
        bool enabled;
        uint48 validAfter;
        uint48 validUntil;
    }

    event Grant(
        address indexed account,
        address indexed operator,
        ValidationData data
    );
    event Revoke(address indexed account, address indexed operator);
    event NewMetadata(address indexed account, bytes metadata);

    function grant(address operator, ValidationData memory data) external;

    function revoke(address operator) external;

    function getValidationData(
        address account,
        address validator
    ) external returns (ValidationData memory);

    function setMetadata(bytes calldata metadata) external;
}
