//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "../interfaces/IAccountValidator.sol";
import "../interfaces/IOpenId3Account.sol";

abstract contract AccountAdminBase is IERC165, IAccountValidator {
    using Address for address;

    error OnlyAdminAllowed();

    modifier onlyAdminMode() {
        if (
            ERC165Checker.supportsInterface(
                msg.sender,
                type(IOpenId3Account).interfaceId
            ) && IOpenId3Account(msg.sender).getMode() != 0x00
        ) {
            revert OnlyAdminAllowed();
        }
        _;
    }

    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return interfaceId == type(IAccountValidator).interfaceId;
    }
}
