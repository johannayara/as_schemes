const { expect } = require("chai");
const { ethers } = require("hardhat");
const { solidityPackedKeccak256} = require("ethers");


describe("TimedMultisigWallet", function () {
  let walletContract, alice, bob, other;
  const TEN_ETH = ethers.parseEther("10.0");
  

  beforeEach(async function () {
    const latestBlock = await ethers.provider.getBlock("latest");
    const timeout = latestBlock.timestamp + 3600; // set a 1 hour timeout
    [alice, bob, other] = await ethers.getSigners();

    const TimedMultisigWallet = await ethers.getContractFactory("TimedMultisigWallet");
    walletContract = await TimedMultisigWallet.connect(alice).deploy(
      alice.address,
      bob.address,
      timeout,
      { value: TEN_ETH }
    );

    await walletContract.deploymentTransaction().wait();
  });

  it("Should allow Alice and Bob to withdraw with both signatures", async function () {
    const message = solidityPackedKeccak256(["string"], ["Withdraw funds from TimedMultisigWallet"]);

    const sigAlice = await alice.signMessage(ethers.getBytes(message));
    const sigBob = await bob.signMessage(ethers.getBytes(message));

    const contractBalanceBefore = await ethers.provider.getBalance(walletContract.target);
    expect(contractBalanceBefore).to.equal(TEN_ETH);

    // Bob initiates the withdrawal
    await walletContract.connect(bob).multisigWithdraw(message, sigAlice, sigBob);

    const contractBalanceAfter = await ethers.provider.getBalance(walletContract.target);
    expect(contractBalanceAfter).to.equal(0);
  });

  it("Should allow Alice to withdraw after timeout", async function () {
    // Fast-forward time
    await ethers.provider.send("evm_increaseTime", [3601]); // > 1 hour
    await ethers.provider.send("evm_mine", []);

    await walletContract.connect(alice).withdrawAfterTimeout();
    const contractBalanceAfter = await ethers.provider.getBalance(walletContract.target);
    expect(contractBalanceAfter).to.equal(0);
  });

  it("Should allow Alice to withdraw only once after timeout", async function () {
  // Fast-forward time past the unlockTime
  await ethers.provider.send("evm_increaseTime", [3601]);
  await ethers.provider.send("evm_mine", []);

  // First withdrawal should succeed
  await expect(walletContract.connect(alice).withdrawAfterTimeout()).to.not.be.reverted;

  // Contract balance should now be zero
  const balance = await ethers.provider.getBalance(walletContract.target);
  expect(balance).to.equal(0);

  // Second attempt should fail with "Funds already withdrawn"
  await expect(
    walletContract.connect(alice).withdrawAfterTimeout()
  ).to.be.revertedWith("Funds already withdrawn");
});

  it("Should not allow withdraw after timeout with multisig", async function () {
    const message = solidityPackedKeccak256(["string"], ["Withdraw funds from TimedMultisigWallet"]);

    const sigAlice = await alice.signMessage(ethers.getBytes(message));
    const sigBob = await bob.signMessage(ethers.getBytes(message));

    // Fast-forward past timeout
    await ethers.provider.send("evm_increaseTime", [3601]);
    await ethers.provider.send("evm_mine", []);

    await expect(
      walletContract.connect(bob).multisigWithdraw(message, sigAlice, sigBob)
    ).to.be.revertedWith("Too late for multisig");
  });

  it("Should revert with invalid signatures", async function () {
    const message = solidityPackedKeccak256(["string"], ["Withdraw funds from TimedMultisigWallet"]);
    const invalidSig = await other.signMessage(ethers.getBytes(message)); // signature by unrelated signer

    await expect(
      walletContract.connect(bob).multisigWithdraw(message, invalidSig, invalidSig)
    ).to.be.revertedWith("Invalid signatures");
  });

  it("Should revert on duplicate withdrawal", async function () {
    const message =  solidityPackedKeccak256(["string"], ["Withdraw funds from TimedMultisigWallet"]);
    const sigAlice = await alice.signMessage(ethers.getBytes(message));
    const sigBob = await bob.signMessage(ethers.getBytes(message));

    // First successful withdrawal
    await walletContract.connect(bob).multisigWithdraw(message, sigAlice, sigBob);

    // Try to withdraw again with same signatures
    await expect(
      walletContract.connect(bob).multisigWithdraw(message, sigAlice, sigBob)
    ).to.be.revertedWith("Funds already withdrawn");
  });

  it("Should revert withdrawal by non-participant", async function () {
    const message = solidityPackedKeccak256(["string"], ["Withdraw funds from TimedMultisigWallet"]);
    const sigAlice = await alice.signMessage(ethers.getBytes(message));
    const sigBob = await bob.signMessage(ethers.getBytes(message));

    // 'other' tries to call multisigWithdraw
    await expect(
      walletContract.connect(other).multisigWithdraw(message, sigAlice, sigBob)
    ).to.be.revertedWith("Not an authorized participant");
  });

  it("Should revert if Alice tries to reclaim funds before timeout", async function () {
    await expect(
      walletContract.connect(alice).withdrawAfterTimeout()
    ).to.be.revertedWith("Too early");
  });

});
