require("@nomicfoundation/hardhat-toolbox");
require("hardhat-gas-reporter");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  gasReporter: {
    enabled: true,
    currency: "USD",
    gasPrice: 7, // hardcoded gas price in gwei
    token: "ETH",
    tokenPrice: 3000, // hardcoded ETH price
    currencyDisplayPrecision: 6, 
    includeIntrinsicGas: true,
    L1:"ethereum",
  },
};
