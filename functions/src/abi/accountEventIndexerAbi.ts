export const accountEventIndexerAbi = [
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
        indexed: false,
        internalType: "address",
        name: "oldAdmin",
        type: "address",
      },
      {
        indexed: false,
        internalType: "address",
        name: "newAdmin",
        type: "address",
      },
    ],
    name: "NewAdmin",
    type: "event",
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
        indexed: false,
        internalType: "string",
        name: "metadata",
        type: "string",
      },
    ],
    name: "NewMetadata",
    type: "event",
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
        indexed: false,
        internalType: "bytes32",
        name: "operatorHash",
        type: "bytes32",
      },
      {
        indexed: false,
        internalType: "bytes",
        name: "operators",
        type: "bytes",
      },
    ],
    name: "NewOperators",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "oldAdmin",
        type: "address",
      },
      {
        internalType: "address",
        name: "admin",
        type: "address",
      },
    ],
    name: "newAdmin",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "metadata",
        type: "string",
      },
    ],
    name: "newMetadata",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "operatorHash",
        type: "bytes32",
      },
      {
        internalType: "bytes",
        name: "operators",
        type: "bytes",
      },
    ],
    name: "newOperators",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;
