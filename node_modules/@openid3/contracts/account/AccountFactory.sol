//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./AccountProxy.sol";
import "../interfaces/IAccountProxy.sol";
import "../interfaces/IOpenId3Account.sol";

contract AccountFactory {
    event AccountDeployed(address account);

    address public immutable accountProxy;
    address public immutable accountImpl;

    constructor(address _accountProxy, address _accountImpl) {
        accountProxy = _accountProxy;
        accountImpl = _accountImpl;
    }

    // we cannot set operator and metadata in the same transaction
    // if we don't use operator to derive the salt. This is to
    // prevent middleman attack. Consider the case where the attacker
    // knows your admin data, they will be able to deploy your account
    // with their operator and move the money, since the signature
    // validation accepts the operator's signature
    function cloneWithAdminOnly(
        bytes memory adminData
    ) external returns (address proxy) {
        bytes32 salt = keccak256(adminData);
        proxy = Clones.cloneDeterministic(accountProxy, salt);
        address manager = IOpenId3Account(accountImpl).getOperator();
        bytes memory accountData = abi.encodeWithSelector(
            IOpenId3Account.initialize.selector,
            adminData,
            abi.encodePacked(manager), // operator data
            bytes("") // metadata
        );
        IAccountProxy(proxy).initProxy(accountImpl, accountData);
        emit AccountDeployed(proxy);
    }

    function clone(bytes memory accountData) external returns (address proxy) {
        bytes32 salt = keccak256(accountData);
        proxy = Clones.cloneDeterministic(accountProxy, salt);
        IAccountProxy(proxy).initProxy(accountImpl, accountData);
        emit AccountDeployed(proxy);
    }

    function predictClonedAddress(
        bytes32 salt
    ) external view returns (address) {
        return Clones.predictDeterministicAddress(accountProxy, salt);
    }

    function deploy(bytes memory accountData) external returns (address proxy) {
        bytes32 salt = keccak256(accountData);
        bytes memory bytecode = type(AccountProxy).creationCode;
        assembly ("memory-safe") {
            proxy := create2(0x0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        if (proxy == address(0)) {
            revert();
        }
        IAccountProxy(proxy).initProxy(accountImpl, accountData);
        emit AccountDeployed(proxy);
    }

    function predictDeployedAddress(
        bytes memory accountData
    ) external view returns (address) {
        bytes32 salt = keccak256(accountData);
        bytes memory bytecode = type(AccountProxy).creationCode;
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint(hash)));
    }
}
