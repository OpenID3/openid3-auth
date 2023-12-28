//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Strings.sol";
import "../interfaces/IPlonkVerifier.sol";
import "../interfaces/OpenIdZkProofPublicInput.sol";
import "../interfaces/IRsaCert.sol";
import "../lib/RsaVerifier.sol";
import "./RsaCertRegistration.sol";
import "./AccountAdminBase.sol";

contract GoogleZkAdmin is AccountAdminBase, RsaCertRegistration {
    using Strings for uint256;

    event AccountLinked(address indexed account, bytes32 indexed idHash);

    error InvalidRsaKey(string key, bytes32 keyId);

    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    bytes32 constant GOOGLE_PROVIDER = keccak256("google");

    bytes32 public constant MASK =
        hex"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    uint256 public constant JWT_TTL = 1800; // 30 mins

    struct GoogleZkValidationData {
        OpenIdZkProofPublicInput input;
        bytes32 circuitDigest;
        bytes proof;
    }

    IPlonkVerifier public immutable plonkVerifier;

    mapping(address => bytes32) private _accounts;
    mapping(address => bytes32) private _proofCache;

    constructor(address _plonkVerifier) {
        plonkVerifier = IPlonkVerifier(_plonkVerifier);
    }

    function linkAccount(bytes32 idHash) external onlyAdminMode {
        _accounts[msg.sender] = idHash;
        emit AccountLinked(msg.sender, idHash);
    }

    function getLinkedAccountHash(
        address account
    ) public view returns (bytes32) {
        return _accounts[account];
    }

    function cacheProof(
        address[] calldata accounts,
        bytes32[] calldata challenges,
        OpenIdZkProofPublicInput[] calldata inputs,
        bytes32 circuitDigest,
        bytes calldata proof
    ) external {
        if (accounts.length != inputs.length || accounts.length != challenges.length) {
            revert("Invalid input");
        }
        bytes memory totalBytes;
        for (uint256 i = 0; i < inputs.length; i++) {
            bytes32 accountHash = getLinkedAccountHash(accounts[i]);
            totalBytes = abi.encodePacked(
                totalBytes,
                inputs[i].jwtHeaderAndPayloadHash,
                inputs[i].kidHash, // kid
                accountHash, // iss+aud+sub
                sha256(bytes(toHexString(uint256(challenges[i])))), // nonce
                sha256(bytes(inputs[i].iat)) // iat
            );
            uint256 iat = _stringToUint(inputs[i].iat);
            _proofCache[accounts[i]] = keccak256(
                abi.encodePacked(challenges[i], iat)
            );
            if (!_validateJwtSignature(inputs[i])) {
                revert("Invalid jwt signature");
            }
        }
        bytes32 inputHashMasked = sha256(totalBytes) & MASK;
        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = uint256(circuitDigest);
        publicInputs[1] = uint256(inputHashMasked);
        if (!plonkVerifier.verify(proof, publicInputs)) {
            revert("Invalid proof");
        }
    }

    function validateSignatureViaCache(
        bytes32 challenge,
        bytes calldata validationData
    ) external view returns (uint256) {
        uint256 iat = abi.decode(validationData, (uint256));
        bytes32 cachedProof = keccak256(abi.encodePacked(challenge, iat));
        if (_proofCache[msg.sender] == cachedProof) {
            return (iat + JWT_TTL) << 160;
        } else {
            return 1;
        }
    }

    function validateSignature(
        bytes32 challenge,
        bytes calldata validationData
    ) external view override returns (uint256) {
        GoogleZkValidationData memory data = abi.decode(
            validationData,
            (GoogleZkValidationData)
        );
        if (!_validateJwtSignature(data.input)) {
            return 1;
        }
        bytes32 inputHashMasked = _genInputHash(challenge, data.input);
        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = uint256(data.circuitDigest);
        publicInputs[1] = uint256(inputHashMasked);
        if (plonkVerifier.verify(data.proof, publicInputs)) {
            uint256 validUntil = _stringToUint(data.input.iat) + JWT_TTL;
            return validUntil << 160;
        } else {
            return 1;
        }
    }

    function _stringToUint(
        string memory s
    ) internal pure returns (uint256 result) {
        bytes memory b = bytes(s);
        uint256 i;
        result = 0;
        for (i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        bytes memory buffer = new bytes(64);
        for (uint256 i = 64; i > 0; --i) {
            buffer[i - 1] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        return string(buffer);
    }

    function _validateJwtSignature(
        OpenIdZkProofPublicInput memory input
    ) internal view returns (bool) {
        address cert = getCert(input.kidHash);
        IRsaCert rsaCert = IRsaCert(cert);
        if (cert == address(0) || rsaCert.getIssuer() != GOOGLE_PROVIDER) {
            return false;
        }
        return RsaVerifier.pkcs1Sha256(
                input.jwtHeaderAndPayloadHash,
                input.jwtSignature,
                rsaCert.E(),
                rsaCert.N()
        );
    }

    function _buildInputBytes(
        bytes32 challenge,
        OpenIdZkProofPublicInput memory input
    ) internal returns (bytes memory) {
        
    }

    function _genInputHash(
        bytes32 challenge,
        OpenIdZkProofPublicInput memory input
    ) internal view returns (bytes32) {
        bytes32 accountHash = getLinkedAccountHash(msg.sender);
        bytes32 inputHash = sha256(
            abi.encodePacked(
                input.jwtHeaderAndPayloadHash,
                input.kidHash, // kid
                accountHash, // iss+aud+sub
                sha256(bytes(toHexString(uint256(challenge)))), // nonce
                sha256(bytes(input.iat)) // iat
            )
        );
        return inputHash & MASK;
    }
}
