// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { IEVMVerifier } from '@ensdomains/evm-verifier/contracts/IEVMVerifier.sol';

/**
 * A verifier that answers with fewer values than it was asked for. A well-behaved verifier
 * always returns one value per command, so this stands in for a malicious or broken one and
 * proves `EVMFetchTarget` rejects the response instead of passing a short array to the callback.
 */
contract MockShortVerifier is IEVMVerifier {
    string[] _gatewayURLs;

    constructor(string[] memory urls) {
        _gatewayURLs = urls;
    }

    function gatewayURLs() external view returns (string[] memory) {
        return _gatewayURLs;
    }

    function getStorageValues(
        address,
        bytes32[] memory,
        bytes[] memory,
        bytes memory
    ) external pure returns (bytes[] memory values) {
        return new bytes[](0);
    }
}
