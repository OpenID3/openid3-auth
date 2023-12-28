//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../interfaces/IRsaCertRegistration.sol";
import "./RsaCert.sol";

abstract contract RsaCertRegistration is IRsaCertRegistration, Ownable {
    event CertAdded(bytes32 indexed kidHash, address indexed cert);
    event CertRevoked(bytes32 indexed kidHash);

    mapping(bytes32 => address) private certs;

    function register(
        bytes32 kidHash,
        bytes32 provider,
        bytes memory N
    ) external onlyOwner {
        RsaCert cert = new RsaCert(provider, N);
        certs[kidHash] = address(cert);
        emit CertAdded(kidHash, address(cert));
    }

    function revoke(bytes32 kidHash) external onlyOwner {
        certs[kidHash] = address(0);
        emit CertRevoked(kidHash);
    }

    function getCert(bytes32 kidHash) public view override returns (address) {
        return certs[kidHash];
    }
}
