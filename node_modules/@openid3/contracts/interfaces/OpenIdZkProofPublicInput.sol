//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

struct OpenIdZkProofPublicInput {
    bytes32 kidHash;
    string iat;
    bytes32 jwtHeaderAndPayloadHash;
    bytes jwtSignature;
}
