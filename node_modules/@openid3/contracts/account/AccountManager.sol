//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../interfaces/IAccountManager.sol";
import "../admin/AccountAdminBase.sol";

contract AccountManager is IAccountManager, AccountAdminBase {
    using ECDSA for bytes32;

    mapping(address => mapping(address => ValidationData)) private _validators;

    function initAccount(
        address validator,
        ValidationData memory data,
        bytes calldata metadata
    ) external onlyAdminMode {
        grant(validator, data);
        setMetadata(metadata);
    }

    function grant(
        address validator,
        ValidationData memory data
    ) public override onlyAdminMode {
        _validators[msg.sender][validator] = data;
        emit Grant(msg.sender, validator, data);
    }

    function revoke(address validator) external override onlyAdminMode {
        _validators[msg.sender][validator].enabled = false;
        emit Revoke(msg.sender, validator);
    }

    function setMetadata(
        bytes calldata metadata
    ) public override onlyAdminMode {
        emit NewMetadata(msg.sender, metadata);
    }

    function getValidationData(
        address account,
        address validator
    ) external view override returns (ValidationData memory) {
        return _validators[account][validator];
    }

    function validateSignature(
        bytes32 challenge,
        bytes calldata validationData
    ) public view override returns (uint256) {
        address validator = address(bytes20(validationData[0:20]));
        ValidationData memory data = _validators[msg.sender][validator];
        if (data.enabled == false) {
            return 1;
        }
        return
            SignatureChecker.isValidSignatureNow(
                validator,
                challenge.toEthSignedMessageHash(),
                validationData[20:]
            )
                ? _genValidationData(data)
                : 1;
    }

    function _genValidationData(
        ValidationData memory data
    ) private pure returns (uint256) {
        return
            (uint256(data.validAfter) << 208) +
            (uint256(data.validUntil) << 160);
    }
}
