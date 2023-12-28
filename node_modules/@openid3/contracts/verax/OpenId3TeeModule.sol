//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "linea-attestation-registry-contracts/src/abstracts/AbstractModule.sol";

contract OpenId3TeeModule is AbstractModule {
    using ECDSA for bytes32;

    error InvalidSchemaId();
    error UnsupportedProvider();
    error InvalidSignature();
    error AlreadyAttested();

    event Attested(bytes32 indexed accAndTypeHash, bytes subject);

    // keccak256("bytes32 providerHash, bytes32 accountHash");
    bytes32 constant public SCHEMA_ID =
        hex"912214269b9b891a0d7451974030ba13207d3bf78e515351609de9dd8a339686";

    // keccak256("google");
    bytes32 constant public GOOGLE_PROVIDER =
        hex"8f2f90d8304f6eb382d037c47a041d8c8b4d18bdd8b082fa32828e016a584ca7";

    address public immutable signer;
    mapping(bytes32 => bool) private _attested;

    constructor(address _signer) {
        signer = _signer;
    }

    function run(
        AttestationPayload memory attestationPayload,
        bytes memory validationPayload,
        address /* txSender */,
        uint256 /* value */
    ) public virtual override {
        if (attestationPayload.schemaId != SCHEMA_ID) {
            revert InvalidSchemaId();
        }
        (bytes32 provider,) = abi.decode(
            attestationPayload.attestationData, (bytes32, bytes32));
        if (provider != GOOGLE_PROVIDER) {
            revert UnsupportedProvider();
        }
        bytes32 message = keccak256(
            abi.encodePacked(
                attestationPayload.attestationData,
                attestationPayload.subject
            )
        );
        bytes32 accAndTypeHash = keccak256(
            attestationPayload.attestationData);
        _validateAttested(accAndTypeHash);
        if (!SignatureChecker.isValidSignatureNow(
              signer,
              message.toEthSignedMessageHash(),
              validationPayload)) {
          revert InvalidSignature();
        }
        emit Attested(accAndTypeHash, attestationPayload.subject);
    }

    function _validateAttested(bytes32 accAndTypeHash) internal {
        if (_attested[accAndTypeHash]) {
            revert AlreadyAttested();
        }
        _attested[accAndTypeHash] = true;
    }
}
