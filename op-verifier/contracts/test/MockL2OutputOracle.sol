// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Types } from "@eth-optimism/contracts-bedrock/src/libraries/Types.sol";

/**
 * Stands in for Optimism's L2OutputOracle so `OPVerifier` can be tested without an OP devnet.
 * The real oracle is fed by proposers; here the output root is set directly by the test.
 */
contract MockL2OutputOracle {
    mapping(uint256 => Types.OutputProposal) private outputs;

    function setL2Output(
        uint256 l2OutputIndex,
        bytes32 outputRoot,
        uint128 timestamp,
        uint128 l2BlockNumber
    ) external {
        outputs[l2OutputIndex] = Types.OutputProposal({
            outputRoot: outputRoot,
            timestamp: timestamp,
            l2BlockNumber: l2BlockNumber
        });
    }

    function getL2Output(uint256 _l2OutputIndex) external view returns (Types.OutputProposal memory) {
        return outputs[_l2OutputIndex];
    }
}
