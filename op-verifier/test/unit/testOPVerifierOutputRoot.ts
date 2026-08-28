import { expect } from 'chai';
import { AbiCoder, Contract, Signer, keccak256 } from 'ethers';
import { ethers } from 'hardhat';

/**
 * Unit tests for the output-root check in `OPVerifier`, using a stubbed L2OutputOracle so they
 * run on a plain in-process Hardhat network. The end-to-end suite in `test/devnet` covers the
 * proving path against a real OP devnet; this covers the gate that gets you there.
 */

const coder = AbiCoder.defaultAbiCoder();

// Types.OutputRootProof, as `Hashing.hashOutputRootProof` encodes it.
const OUTPUT_ROOT_PROOF_TYPE =
  'tuple(bytes32 version, bytes32 stateRoot, bytes32 messagePasserStorageRoot, bytes32 latestBlockhash)';

const PROOF_TYPES = [
  `tuple(uint256 l2OutputIndex, ${OUTPUT_ROOT_PROOF_TYPE} outputRootProof)`,
  'tuple(bytes stateTrieWitness, bytes[] storageProofs)',
];

type OutputRootProof = {
  version: string;
  stateRoot: string;
  messagePasserStorageRoot: string;
  latestBlockhash: string;
};

function hashOutputRootProof(proof: OutputRootProof): string {
  return keccak256(
    coder.encode(
      ['bytes32', 'bytes32', 'bytes32', 'bytes32'],
      [
        proof.version,
        proof.stateRoot,
        proof.messagePasserStorageRoot,
        proof.latestBlockhash,
      ]
    )
  );
}

function encodeProof(
  l2OutputIndex: number,
  outputRootProof: OutputRootProof,
  // A well-formed but empty witness: enough to decode, not enough to prove anything.
  stateTrieWitness = coder.encode(['bytes[]'], [[]]),
  storageProofs: string[] = []
): string {
  return coder.encode(PROOF_TYPES, [
    [
      l2OutputIndex,
      [
        outputRootProof.version,
        outputRootProof.stateRoot,
        outputRootProof.messagePasserStorageRoot,
        outputRootProof.latestBlockhash,
      ],
    ],
    [stateTrieWitness, storageProofs],
  ]);
}

/** Returns the 4-byte selector of a custom error signature. */
function selector(signature: string): string {
  return ethers.id(signature).slice(0, 10);
}

function findRevertData(err: unknown, depth = 0): string | undefined {
  if (err === null || err === undefined || depth > 8) return undefined;
  if (typeof err === 'string') {
    return /^0x[0-9a-fA-F]{8,}$/.test(err) ? err : undefined;
  }
  if (typeof err !== 'object') return undefined;
  const record = err as Record<string, unknown>;
  for (const key of ['data', 'error', 'info', 'cause', 'value', 'body']) {
    if (key in record) {
      const found = findRevertData(record[key], depth + 1);
      if (found !== undefined) return found;
    }
  }
  return undefined;
}

describe('OPVerifier output root verification', () => {
  let signer: Signer;
  let oracle: Contract;
  let verifier: Contract;

  // An arbitrary but well-formed output root proof. The state root is not backed by a real
  // trie, which is fine: these tests never get as far as verifying one.
  const outputRootProof: OutputRootProof = {
    version: ethers.ZeroHash,
    stateRoot: ethers.id('state root'),
    messagePasserStorageRoot: ethers.id('message passer storage root'),
    latestBlockhash: ethers.id('latest blockhash'),
  };

  beforeEach(async () => {
    [signer] = await ethers.getSigners();

    const oracleFactory = await ethers.getContractFactory(
      'MockL2OutputOracle',
      signer
    );
    oracle = await oracleFactory.deploy();

    const verifierFactory = await ethers.getContractFactory(
      'OPVerifier',
      signer
    );
    verifier = await verifierFactory.deploy(
      ['test:'],
      await oracle.getAddress()
    );
  });

  it('exposes the gateway URLs it was constructed with', async () => {
    expect(await verifier.gatewayURLs()).to.deep.equal(['test:']);
  });

  it('rejects a proof whose output root does not match the oracle', async () => {
    // The oracle commits to a different root than the one the caller's proof hashes to.
    await oracle.setL2Output(0, ethers.id('a different output root'), 1, 1);

    await expect(
      verifier.getStorageValues(
        await signer.getAddress(),
        [],
        [],
        encodeProof(0, outputRootProof)
      )
    ).to.be.revertedWithCustomError(verifier, 'OutputRootMismatch');
  });

  it('rejects a proof pointing at an output index the oracle has never seen', async () => {
    // Unset entries read back as a zero proposal, which cannot match any real proof.
    await expect(
      verifier.getStorageValues(
        await signer.getAddress(),
        [],
        [],
        encodeProof(99, outputRootProof)
      )
    ).to.be.revertedWithCustomError(verifier, 'OutputRootMismatch');
  });

  it('clears the output root check when the oracle agrees', async () => {
    // With the oracle committing to exactly this proof's root, the gate passes and the
    // verifier goes on to the state trie. The witness proves nothing, so the call still
    // reverts — but with something other than `OutputRootMismatch`, and that difference is
    // what shows the gate was cleared. Proving a real account is the devnet suite's job.
    await oracle.setL2Output(0, hashOutputRootProof(outputRootProof), 1, 1);

    let reverted = false;
    try {
      await verifier.getStorageValues(
        await signer.getAddress(),
        [],
        [],
        encodeProof(0, outputRootProof)
      );
    } catch (err) {
      reverted = true;
      const data = findRevertData(err);
      if (data !== undefined) {
        expect(data.slice(0, 10)).to.not.equal(
          selector('OutputRootMismatch(uint256,bytes32,bytes32)'),
          'output root check rejected a proof the oracle agreed with'
        );
      }
    }
    expect(reverted, 'expected the call to revert past the output root check')
      .to.be.true;
  });
});
