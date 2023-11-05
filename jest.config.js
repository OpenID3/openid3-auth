module.exports = {
  preset: 'ts-jest',
  testPathIgnorePatterns: ['/node_modules/', '/dist/', "/lib/"],
  testEnvironment: 'node',
  testTimeout: 3000
}
