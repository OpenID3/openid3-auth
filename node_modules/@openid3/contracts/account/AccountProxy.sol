//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Upgrade.sol";
import "@openzeppelin/contracts/proxy/Proxy.sol";
import "../interfaces/IAccountProxy.sol";

/**
 * ignore the receive function warning since it
 * should be defined in implementation
 */
contract AccountProxy is IAccountProxy, Proxy, ERC1967Upgrade {
    error AlreadyInitiated();

    /** We name is initProxy to specify it's for proxy not the implementation */
    function initProxy(address logic, bytes calldata data) external override {
        if (_implementation() != address(0)) {
            revert AlreadyInitiated();
        }
        _upgradeToAndCall(logic, data, false);
    }

    function _implementation() internal view override returns (address) {
        return ERC1967Upgrade._getImplementation();
    }
}
