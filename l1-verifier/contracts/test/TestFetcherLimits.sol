// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { EVMFetcher } from '@ensdomains/evm-verifier/contracts/EVMFetcher.sol';
import { EVMFetchTarget } from '@ensdomains/evm-verifier/contracts/EVMFetchTarget.sol';
import { IEVMVerifier } from '@ensdomains/evm-verifier/contracts/IEVMVerifier.sol';

/**
 * Exercises the bounds checks in `EVMFetcher`. Each function builds a request that runs past
 * one of the library's limits, so none of them should reach the `OffchainLookup` revert that
 * terminates a well-formed request.
 */
contract TestFetcherLimits is EVMFetchTarget {
    using EVMFetcher for EVMFetcher.EVMFetchRequest;

    IEVMVerifier verifier;                  // Slot 0
    address target;

    constructor(IEVMVerifier _verifier, address _target) {
        verifier = _verifier;
        target = _target;
    }

    /// @dev MAX_COMMANDS is 32, so the 33rd `getStatic` is one too many.
    function tooManyCommands() public view {
        EVMFetcher.EVMFetchRequest memory request = EVMFetcher.newFetchRequest(verifier, target);
        for (uint256 i = 0; i < 33; i++) {
            request = request.getStatic(0);
        }
        request.fetch(this.emptyCallback.selector, "");
    }

    /// @dev A command packs a flags byte plus 31 operations; `getStatic` spends two of them,
    ///      so the 31st `element` is the one that runs off the end.
    function commandTooLong() public view {
        EVMFetcher.EVMFetchRequest memory request =
            EVMFetcher.newFetchRequest(verifier, target).getStatic(0);
        for (uint256 i = 0; i < 31; i++) {
            request = request.element(uint256(0));
        }
        request.fetch(this.emptyCallback.selector, "");
    }

    /// @dev Only one command has been issued, so index 5 refers to a value that cannot exist.
    function invalidReference() public view {
        EVMFetcher.newFetchRequest(verifier, target)
            .getStatic(0)
                .ref(5)
            .fetch(this.emptyCallback.selector, "");
    }

    function emptyCallback(bytes[] memory, bytes memory) public pure returns (uint256) {
        return 0;
    }
}
