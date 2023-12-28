//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Strings.sol";
import "../interfaces/IRsaCert.sol";

contract RsaCert is IRsaCert {
    bytes32 immutable private issuer;
    bytes constant public E = hex"010001";
    bytes public N;

    constructor(bytes32 _issuer, bytes memory _N) {
        N = _N;
        issuer = _issuer;
    }

    function getIssuer() external override view returns (bytes32) {
        return issuer;
    }
}