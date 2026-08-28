import { Server } from '@chainlink/ccip-read-server';
import { makeL1Gateway } from '@ensdomains/l1-gateway';
import { HardhatEthersProvider } from '@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider';
import type { HardhatEthersHelpers } from '@nomicfoundation/hardhat-ethers/types';
import { expect } from 'chai';
import {
  AbiCoder,
  BrowserProvider,
  Contract,
  FetchRequest,
  JsonRpcProvider,
  Signer,
  ethers as ethersT,
} from 'ethers';
import { ethers } from 'hardhat';
import { EthereumProvider } from 'hardhat/types';
import request from 'supertest';

type ethersObj = typeof ethersT &
  Omit<HardhatEthersHelpers, 'provider'> & {
    provider: Omit<HardhatEthersProvider, '_hardhatProvider'> & {
      _hardhatProvider: EthereumProvider;
    };
  };

declare module 'hardhat/types/runtime' {
  const ethers: ethersObj;
  interface HardhatRuntimeEnvironment {
    ethers: ethersObj;
  }
}

const coder = AbiCoder.defaultAbiCoder();

// The shape `L1Verifier.getStorageValues` expects its `proof` argument to decode to.
const PROOF_TYPES = [
  'tuple(uint256 blockNo, bytes blockHeader)',
  'tuple(bytes stateTrieWitness, bytes[] storageProofs)',
];

/**
 * Walks an ethers error looking for the revert payload. Which field carries it depends on
 * whether the call failed directly or inside a CCIP-read callback, so check the usual places.
 */
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

/**
 * Asserts that `fn` reverts with the custom error named by `signature`. Compares selectors
 * rather than using `revertedWithCustomError`, because most of these errors are declared in
 * libraries and so never appear in the calling contract's ABI.
 */
async function expectRevert(signature: string, fn: () => Promise<unknown>) {
  const expected = ethers.id(signature).slice(0, 10);
  let result: unknown;
  try {
    result = await fn();
  } catch (err) {
    const data = findRevertData(err);
    if (data === undefined) {
      expect.fail(
        `expected ${signature} (${expected}) but found no revert data in: ${
          (err as Error)?.message ?? String(err)
        }`
      );
    }
    expect(data.slice(0, 10)).to.equal(
      expected,
      `expected ${signature} (${expected}), got revert data ${data.slice(0, 74)}`
    );
    return;
  }
  expect.fail(`expected ${signature} but the call returned ${String(result)}`);
}

describe('L1Verifier error handling', () => {
  let provider: BrowserProvider;
  let signer: Signer;
  let verifier: Contract;
  let l2contract: Contract;
  let target: Contract;

  // Set to rewrite the gateway's response before it reaches the verifier.
  let tamper: ((data: string) => string) | null = null;
  // Records the most recent untampered gateway response.
  let lastProofResponse: string | null = null;

  before(async () => {
    provider = new ethers.BrowserProvider(ethers.provider._hardhatProvider);
    signer = await provider.getSigner(0);
    const gateway = makeL1Gateway(provider as unknown as JsonRpcProvider);
    const server = new Server();
    gateway.add(server);
    const app = server.makeApp('/');
    const getUrl = FetchRequest.createGetUrlFunc();
    ethers.FetchRequest.registerGetUrl(async (req: FetchRequest) => {
      if (req.url != 'test:') return getUrl(req);

      const r = request(app).post('/');
      if (req.hasBody()) {
        r.set('Content-Type', 'application/json').send(
          ethers.toUtf8String(req.body)
        );
      }
      const response = await r;
      const body = response.body;
      if (body && typeof body.data === 'string') {
        lastProofResponse = body.data;
        if (tamper !== null) {
          body.data = tamper(body.data);
        }
      }
      return {
        statusCode: response.statusCode,
        statusMessage: response.ok ? 'OK' : response.statusCode.toString(),
        body: ethers.toUtf8Bytes(JSON.stringify(body)),
        headers: {
          'Content-Type': 'application/json',
        },
      };
    });

    const l1VerifierFactory = await ethers.getContractFactory(
      'L1Verifier',
      signer
    );
    verifier = await l1VerifierFactory.deploy(['test:']);

    const testL2Factory = await ethers.getContractFactory('TestL2', signer);
    l2contract = await testL2Factory.deploy();

    const testL1Factory = await ethers.getContractFactory('TestL1', signer);
    target = await testL1Factory.deploy(
      await verifier.getAddress(),
      await l2contract.getAddress()
    );
    // Mine an empty block so we have something to prove against
    await provider.send('evm_mine', []);
  });

  afterEach(() => {
    tamper = null;
  });

  describe('block header verification', () => {
    it('rejects a proof whose block header does not hash to the claimed block', async () => {
      tamper = (data) => {
        const [proof] = coder.decode(['bytes'], data);
        const [l1Data, stateProof] = coder.decode(PROOF_TYPES, proof);
        // Flip the final byte of the header so keccak256(header) != blockhash(blockNo).
        const header: string = l1Data.blockHeader;
        const corrupted =
          header.slice(0, -2) + (header.slice(-2) === '00' ? '01' : '00');
        const repacked = coder.encode(PROOF_TYPES, [
          [l1Data.blockNo, corrupted],
          [stateProof.stateTrieWitness, stateProof.storageProofs],
        ]);
        return coder.encode(['bytes'], [repacked]);
      };

      await expectRevert(
        'BlockHeaderHashMismatch(uint256,uint256,bytes32,bytes32)',
        () => target.getLatest({ enableCcipRead: true })
      );
    });
  });

  describe('account verification', () => {
    it('rejects a proof for an address with no account in the state trie', async () => {
      // An address that has never been touched, so the gateway can only produce an
      // exclusion proof for it.
      const emptyAccount = '0x1234567890AbcdEF1234567890aBcdef12345678';
      const testL1Factory = await ethers.getContractFactory('TestL1', signer);
      const orphan = await testL1Factory.deploy(
        await verifier.getAddress(),
        emptyAccount
      );
      await provider.send('evm_mine', []);

      await expectRevert('AccountNotFound(address)', () =>
        orphan.getLatest({ enableCcipRead: true })
      );
    });
  });

  describe('command decoding', () => {
    it('rejects a command containing an unrecognised opcode', async () => {
      // Capture a proof from a call we know succeeds, then replay it against a command
      // whose first instruction uses an opcode the VM does not define.
      lastProofResponse = null;
      await target.getLatest({ enableCcipRead: true });
      expect(
        lastProofResponse,
        'expected to capture a gateway response'
      ).to.be.a('string');
      const [proof] = coder.decode(['bytes'], lastProofResponse as string);

      // Byte 0 is flags; byte 1 is the first instruction. 0x60 is opcode 3, which is
      // not one of FOLLOW_CONST / FOLLOW_REF / ADD_CONST.
      const badCommand = '0x0060' + 'ff'.repeat(30);
      const l2Address = await l2contract.getAddress();

      await expectRevert('UnknownOpcode(uint8)', () =>
        verifier.getStorageValues(l2Address, [badCommand], [], proof)
      );
    });
  });

  describe('verifier response validation', () => {
    it('rejects a verifier that returns fewer values than there were commands', async () => {
      const mockFactory = await ethers.getContractFactory(
        'MockShortVerifier',
        signer
      );
      const mock = await mockFactory.deploy(['test:']);

      const testL1Factory = await ethers.getContractFactory('TestL1', signer);
      const misled = await testL1Factory.deploy(
        await mock.getAddress(),
        await l2contract.getAddress()
      );
      await provider.send('evm_mine', []);

      await expectRevert('ResponseLengthMismatch(uint256,uint256)', () =>
        misled.getLatest({ enableCcipRead: true })
      );
    });
  });

  describe('request construction limits', () => {
    let limits: Contract;

    before(async () => {
      const factory = await ethers.getContractFactory(
        'TestFetcherLimits',
        signer
      );
      limits = await factory.deploy(
        await verifier.getAddress(),
        await l2contract.getAddress()
      );
    });

    it('rejects more than MAX_COMMANDS commands', async () => {
      await expectRevert('TooManyCommands(uint256)', () =>
        limits.tooManyCommands()
      );
    });

    it('rejects a command with more operations than fit in a word', async () => {
      await expectRevert('CommandTooLong()', () => limits.commandTooLong());
    });

    it('rejects a reference to a command that was never issued', async () => {
      await expectRevert('InvalidReference(uint256,uint256)', () =>
        limits.invalidReference()
      );
    });
  });
});
