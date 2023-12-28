//SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC165.sol";

import "@account-abstraction/contracts/core/BaseAccount.sol";
import "@account-abstraction/contracts/samples/callback/TokenCallbackHandler.sol";

import "../interfaces/IAccountValidator.sol";
import "../interfaces/IAccountManager.sol";
import "../interfaces/IOpenId3Account.sol";

library OpenId3AccountStorage {
    bytes32 internal constant STORAGE_SLOT = keccak256("openid3.account");

    struct Layout {
        address admin;
        address operator;
        uint8 mode;
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = STORAGE_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

contract OpenId3Account is
    IOpenId3Account,
    BaseAccount,
    TokenCallbackHandler,
    UUPSUpgradeable,
    Initializable
{
    using Address for address;
    using ECDSA for bytes32;

    error OnlyAdminAllowed();
    error NotAuthorized();
    error InvalidMode(uint8 mode);
    error WrongArrayLength();

    event NewAdmin(address indexed oldAdmin, address indexed newAdmin);
    event NewOperator(address indexed oldOperator, address indexed newOperator);

    IEntryPoint private immutable _entryPoint;
    address private immutable _defaultAdmin;
    address public immutable accountManager;

    modifier onlyEntryPointOrSelf() {
        if (
            msg.sender != address(entryPoint()) && msg.sender != address(this)
        ) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyAdminMode() {
        if (OpenId3AccountStorage.layout().mode != 0x00) {
            revert OnlyAdminAllowed();
        }
        _;
    }

    constructor(address entryPoint_, address admin_, address manager_) {
        _entryPoint = IEntryPoint(entryPoint_);
        accountManager = manager_;
        _defaultAdmin = admin_;
        _disableInitializers();
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    function initialize(
        bytes calldata adminData,
        bytes calldata operatorData,
        bytes calldata metadata
    ) public virtual override initializer {
        _setAdmin(
            address(bytes20(adminData[0:20])),
            adminData[20:]
        );
        _setOperator(
            address(bytes20(operatorData[0:20])),
            operatorData[20:]
        );
        IAccountManager(accountManager).setMetadata(metadata);
    }

    function getMode() external view override returns (uint8) {
        return OpenId3AccountStorage.layout().mode;
    }

    function getAdmin() public view override returns (address) {
        address admin = OpenId3AccountStorage.layout().admin;
        return admin == address(0) ? _defaultAdmin : admin;
    }

    function getOperator() public view returns (address) {
        address operator = OpenId3AccountStorage.layout().operator;
        return operator == address(0) ? accountManager : operator;
    }

    function setAdmin(
        address admin,
        bytes memory adminData
    ) public onlyEntryPointOrSelf onlyAdminMode {
        address oldAdmin = getAdmin();
        _setAdmin(admin, adminData);
        emit NewAdmin(oldAdmin, admin);
    }

    function setOperator(
        address operator,
        bytes memory operatorData
    ) public onlyEntryPointOrSelf onlyAdminMode {
        address oldOperator = getOperator();
        _setOperator(operator, operatorData);
        emit NewOperator(oldOperator, operator);
    }

    function _setAdmin(
        address newAdmin,
        bytes memory adminData
    ) internal {
        if (adminData.length > 0) {
            _call(newAdmin, 0, adminData);
        }
        if (newAdmin == _defaultAdmin) {
            OpenId3AccountStorage.layout().admin = address(0);
        } else {
            OpenId3AccountStorage.layout().admin = newAdmin;
        }
    }

    function _setOperator(
        address newOperator,
        bytes memory operatorData
    ) internal {
        if (operatorData.length > 0) {
            _call(newOperator, 0, operatorData);
        }
        if (newOperator == accountManager) {
            OpenId3AccountStorage.layout().operator = address(0);
        } else {
            OpenId3AccountStorage.layout().operator = newOperator;
        }
    }

    /** UUPSUpgradeable */

    function _authorizeUpgrade(
        address /* newImplementation */
    ) internal view override onlyEntryPointOrSelf onlyAdminMode {}

    function implementation() external view returns (address) {
        return _getImplementation();
    }

    /** Executable  */

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external onlyEntryPointOrSelf {
        _call(dest, value, func);
    }

    function executeBatch(
        address[] calldata dest,
        uint256[] memory value,
        bytes[] calldata func
    ) external onlyEntryPointOrSelf {
        if (dest.length != value.length || value.length != func.length) {
            revert WrongArrayLength();
        }
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], value[i], func[i]);
        }
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 uoHash
    ) internal virtual override returns (uint256 validationData) {
        uint8 mode = uint8(userOp.signature[0]);
        OpenId3AccountStorage.layout().mode = mode;
        if (mode == 0x00) {
            // admin mode
            address admin = getAdmin();
            return _validateSignature(admin, uoHash, userOp.signature[1:]);
        } else if (mode == 0x01) {
            // operator mode
            address operator = getOperator();
            return _validateSignature(operator, uoHash, userOp.signature[1:]);
        } else {
            revert InvalidMode(mode);
        }
    }

    function _validateSignature(
        address signer,
        bytes32 uoHash,
        bytes calldata signature
    ) internal virtual returns (uint256) {
        if (
            signer.isContract() &&
            IERC165(signer).supportsInterface(
                type(IAccountValidator).interfaceId
            )
        ) {
            return
                IAccountValidator(signer).validateSignature(uoHash, signature);
        } else {
            return
                SignatureChecker.isValidSignatureNow(
                    signer,
                    uoHash.toEthSignedMessageHash(),
                    signature
                )
                    ? 0
                    : 1;
        }
    }

    /** Entrypoint related */

    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) external onlyEntryPointOrSelf {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /* help functions */

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function supportsInterface(bytes4 interfaceId) public pure override returns(bool) {
        return interfaceId == type(IOpenId3Account).interfaceId ||
            interfaceId == type(IERC721Receiver).interfaceId ||
            interfaceId == type(IERC1155Receiver).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }
}
