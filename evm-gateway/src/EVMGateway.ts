import type { HandlerDescription } from '@chainlink/ccip-read-server';
import type { Fragment, Interface, JsonFragment } from '@ethersproject/abi';
import {
  concat,
  dataSlice,
  getBytes,
  solidityPackedKeccak256,
  toBigInt,
  zeroPadValue,
} from 'ethers';

import type { IProofService, ProvableBlock } from './IProofService.js';

const OP_FOLLOW_CONST = 0 << 5;
const OP_FOLLOW_REF = 1 << 5;
const OP_ADD_CONST = 2 << 5;
const OP_END = 0xff;

/**
 * Limits on the caller-supplied parts of a `getStorageSlots` request.
 *
 * The on-chain client library (EVMFetcher.sol) already caps itself at 32
 * commands and 32 constants, but the gateway is an unauthenticated HTTP
 * endpoint that anyone can call directly without going through that library,
 * so it has to enforce the same bounds itself.
 */
const MAX_COMMANDS = 32;
const MAX_CONSTANTS = 32;

/**
 * The byte length of a dynamic value is read from a storage slot of the
 * contract named in the request, so it is fully attacker-controlled: a
 * contract can write an arbitrary 256-bit word there and claim a length of up
 * to 2^255. Without a cap, `getDynamicValue` would allocate an array of that
 * many slot numbers and then issue one RPC call per slot, exhausting the
 * gateway's memory and flooding its upstream provider.
 *
 * 1024 slots is 32KB of data, far more than any real record needs.
 */
const MAX_DYNAMIC_SLOTS = 1024;

export enum StorageLayout {
  /**
   * address,uint,bytes32,bool
   */
  FIXED,
  /**
   * array,bytes,string
   */
  DYNAMIC,
}

interface StorageElement {
  slots: bigint[];
  value: () => Promise<string>;
  isDynamic: boolean;
}

interface Server {
  add: (
    abi: string | readonly (string | Fragment | JsonFragment)[] | Interface,
    handlers: HandlerDescription[]
  ) => void;
}

function memoize<T>(fn: () => Promise<T>): () => Promise<T> {
  let promise: Promise<T> | undefined;
  return () => {
    if (!promise) {
      promise = fn();
    }
    return promise;
  };
}

// traverse mapping at slot using key solidity-style
// https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays
function followSolidityMapping(slot: bigint, key: string) {
  return BigInt(solidityPackedKeccak256(['bytes', 'uint256'], [key, slot]));
}

// Operands are 5 bits, so they can address 32 entries whether or not the
// caller actually supplied that many. Reading past the end would otherwise
// hand `undefined` to ethers and surface as an opaque 500.
function constant(constants: string[], operand: number): string {
  if (operand >= constants.length) {
    throw new Error(
      `Invalid constant: ${operand} (max ${constants.length - 1})`
    );
  }
  return constants[operand];
}

// see: EVMProofHelper.uint256FromBytes()
function uint256FromBytes(hex: string): bigint {
  return hex === '0x' ? 0n : BigInt(hex.slice(0, 66));
}

export class EVMGateway<T extends ProvableBlock> {
  readonly proofService: IProofService<T>;

  constructor(proofService: IProofService<T>) {
    this.proofService = proofService;
  }

  add(server: Server) {
    const abi = [
      /**
       * This function implements a simple VM for fetching proofs for EVM contract storage data.
       * Programs consist of an array of `commands` and an array of `constants`. Each `command` is a
       * short program that computes the slot number of a single EVM storage value. The gateway then
       * returns a proof of a value at that slot number. Commands can also specify that the value is
       * dynamic-length, in which case the gateway may return proofs for multiple slots in order for
       * the caller to be able to reconstruct the entire value.
       *
       * Each command is a 32 byte value consisting of a single flags byte, followed by 31 instruction
       * bytes. Valid flags are:
       *  - 0x01 - If set, the value to be returned is dynamic length.
       *
       * The VM implements a very simple stack machine, and instructions specify operations that happen on
       * the stack. In addition, the VM has access to the result of previous commands, referred to here
       * as `values`.
       *
       * The most significant 3 bits of each instruction byte are the opcode, and the least significant
       * 5 bits are the operand. The following opcodes are defined:
       *  - 0x00 - `push(constants[operand])`
       *  - 0x20 - `push(values[operand])`
       *  - 0x70 - `halt` - do not process any further instructions for this command.
       *
       * After a `halt` is reached or the end of the command word is reached, the elements on the stack
       * are hashed recursively, starting with the first element pushed, using a process equivalent
       * to the following:
       *   def hashStack(stack):
       *     right = stack.pop()
       *     if(stack.empty()):
       *       return right
       *     return keccak256(concat(hashStack(stack), right))
       *
       * The final result of this hashing operation is used as the base slot number for the storage
       * lookup. This mirrors Solidity's recursive hashing operation for determining storage slot locations.
       */
      'function getStorageSlots(address addr, bytes32[] memory commands, bytes[] memory constants) external view returns(bytes memory witness)',
    ];
    server.add(abi, [
      {
        type: 'getStorageSlots',
        func: async (args) => {
          try {
            const [addr, commands, constants] = args;
            const proofs = await this.createProofs(addr, commands, constants);
            return [proofs];
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
          } catch (e: any) {
            console.log(e.stack);
            throw e;
          }
        },
      },
    ]);
    return server;
  }

  /**
   *
   * @param address The address to fetch storage slot proofs for
   * @param paths Each element of this array specifies a Solidity-style path derivation for a storage slot ID.
   *              See README.md for details of the encoding.
   */
  async createProofs(
    address: string,
    commands: string[],
    constants: string[]
  ): Promise<string> {
    if (commands.length > MAX_COMMANDS) {
      throw new Error(
        `Too many commands: ${commands.length} (max ${MAX_COMMANDS})`
      );
    }
    if (constants.length > MAX_CONSTANTS) {
      throw new Error(
        `Too many constants: ${constants.length} (max ${MAX_CONSTANTS})`
      );
    }
    const block = await this.proofService.getProvableBlock();
    const requests: Promise<StorageElement>[] = [];
    // For each request, spawn a promise to compute the set of slots required
    for (let i = 0; i < commands.length; i++) {
      requests.push(
        this.getValueFromPath(
          block,
          address,
          commands[i],
          constants,
          requests.slice()
        )
      );
    }
    // Resolve all the outstanding requests
    const results = await Promise.all(requests);
    const slots = Array.prototype.concat(
      ...results.map((result) => result.slots)
    );
    return this.proofService.getProofs(block, address, slots);
  }

  private async computeFirstSlot(
    command: string,
    constants: string[],
    requests: Promise<StorageElement>[]
  ): Promise<{ slot: bigint; isDynamic: boolean }> {
    const commandWord = getBytes(command);
    const flags = commandWord[0];
    const isDynamic = (flags & 0x01) != 0;
    let slot = 0n;
    for (let j = 1; j < 32; j++) {
      const op = commandWord[j];
      if (op === OP_END) break;
      const opcode = op & 0xe0; // upper 3
      const operand = op & 0x1f; // lower 5
      switch (opcode) {
        case OP_FOLLOW_CONST: {
          slot = followSolidityMapping(slot, constant(constants, operand));
          break;
        }
        case OP_FOLLOW_REF: {
          if (operand >= requests.length) {
            throw new Error(
              `Invalid reference: ${operand} (max ${requests.length - 1})`
            );
          }
          const storage = await requests[operand];
          slot = followSolidityMapping(slot, await storage.value());
          break;
        }
        case OP_ADD_CONST: {
          slot += uint256FromBytes(constant(constants, operand));
          break;
        }
        default:
          throw new Error(`Unrecognized opcode: ${opcode}`);
      }
    }
    return { slot, isDynamic };
  }

  private async getDynamicValue(
    block: T,
    address: string,
    slot: bigint
  ): Promise<StorageElement> {
    const firstValue = getBytes(
      await this.proofService.getStorageAt(block, address, slot)
    );
    // Decode Solidity dynamic value encoding
    if (firstValue[31] & 0x01) {
      // Long value: first slot is `length * 2 + 1`, following slots are data.
      // `firstValue` comes from the target contract's storage, so check the
      // claimed length against MAX_DYNAMIC_SLOTS *before* turning it into a
      // Number or allocating anything sized by it.
      const lenBig = (toBigInt(firstValue) - 1n) / 2n;
      if (lenBig > BigInt(MAX_DYNAMIC_SLOTS) * 32n) {
        throw new Error(
          `Dynamic value at slot ${slot} claims a length of ${lenBig} bytes, ` +
            `over the ${MAX_DYNAMIC_SLOTS * 32} byte limit`
        );
      }
      const len = Number(lenBig);
      const hashedSlot = toBigInt(solidityPackedKeccak256(['uint256'], [slot]));
      const slotNumbers = Array(Math.ceil(len / 32))
        .fill(BigInt(hashedSlot))
        .map((i, idx) => i + BigInt(idx));
      return {
        slots: Array.prototype.concat([slot], slotNumbers),
        isDynamic: true,
        value: memoize(async () => {
          const values = await Promise.all(
            slotNumbers.map((slot) =>
              this.proofService.getStorageAt(block, address, slot)
            )
          );
          return dataSlice(concat(values), 0, len);
        }),
      };
    } else {
      // Short value: least significant byte is `length * 2`, other bytes are data.
      const len = firstValue[31] / 2;
      return {
        slots: [slot],
        isDynamic: true,
        value: () => Promise.resolve(dataSlice(firstValue, 0, len)),
      };
    }
  }

  private async getValueFromPath(
    block: T,
    address: string,
    command: string,
    constants: string[],
    requests: Promise<StorageElement>[]
  ): Promise<StorageElement> {
    const { slot, isDynamic } = await this.computeFirstSlot(
      command,
      constants,
      requests
    );

    if (!isDynamic) {
      return {
        slots: [slot],
        isDynamic,
        value: memoize(async () =>
          zeroPadValue(
            await this.proofService.getStorageAt(block, address, slot),
            32
          )
        ),
      };
    } else {
      return this.getDynamicValue(block, address, slot);
    }
  }
}
