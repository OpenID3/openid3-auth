export const passkeyAdminAbi = [
  {
    inputs: [],
    name: "OnlyAdminAllowed",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address",
      },
      {
        indexed: true,
        internalType: "bytes32",
        name: "keyId",
        type: "bytes32",
      },
      {
        components: [
          {
            internalType: "uint256",
            name: "pubKeyX",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "pubKeyY",
            type: "uint256",
          },
        ],
        indexed: false,
        internalType: "struct Passkey",
        name: "pubKey",
        type: "tuple",
      },
      {
        indexed: false,
        internalType: "string",
        name: "passkeyId",
        type: "string",
      },
    ],
    name: "PasskeySet",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "account",
        type: "address",
      },
    ],
    name: "getPasskeyId",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32",
      },
      {
        internalType: "bytes",
        name: "validationData",
        type: "bytes",
      },
    ],
    name: "isValidSignature",
    outputs: [
      {
        internalType: "bytes4",
        name: "",
        type: "bytes4",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "pubKeyX",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "pubKeyY",
            type: "uint256",
          },
        ],
        internalType: "struct Passkey",
        name: "pubKey",
        type: "tuple",
      },
      {
        internalType: "string",
        name: "passkeyId",
        type: "string",
      },
    ],
    name: "setPasskey",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;
