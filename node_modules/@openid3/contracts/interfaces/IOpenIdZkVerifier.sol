//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@account-abstraction/contracts/interfaces/UserOperation.sol";
import "./OpenIdZkProofPublicInput.sol";

interface IOpenIdZkVerifier {
    // @notice get verification key of the open id authenticator
    function getVerificationKeyOfIdp() external view returns(bytes memory);

    // @notice get id hash of account
    function getIdHash(address account) external view returns(bytes32);

    // @notice the function verifies the proof and given a user op
    // @params op: the user operation defined by ERC-4337
    //         input: the zk proof input with JWT info to prove
    //         proof: the generated ZK proof for input and op
    function verify(
        UserOperation memory op,
        OpenIdZkProofPublicInput memory input,
        bytes memory proof
    ) external;

    // @notice the function verifies the aggregated proof give a list of user ops
    // @params ops: a list of user operations defined by ERC-4337
    //         inputs: a list of zk proof input with JWT info to prove
    //         aggregatedProof: the aggregated ZK proof for inputs and ops
    function verifyAggregated(
        UserOperation[] memory ops,
        OpenIdZkProofPublicInput[] memory inputs,
        bytes memory aggregatedProof
    ) external;
}
