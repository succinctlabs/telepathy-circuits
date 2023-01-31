/*
 _____         _                       _     _           
|_   _|  ___  | |  ___   _ __   __ _  | |_  | |_    _  _ 
  | |   / -_) | | / -_) | '_ \ / _` | |  _| | ' \  | || |
  |_|   \___| |_| \___| | .__/ \__,_|  \__| |_||_|  \_, |
                        |_|                         |__/ 

Created on October 28th 2022 by Succinct Labs
Code: https://github.com/succinctlabs/telepathy
License: GPL-3
*/

pragma circom 2.0.5;

include "./inputs.circom";
include "./bls.circom";
include "./constants.circom";
include "./poseidon.circom";
include "./ssz.circom";
include "./sync_committee.circom";

/*
 * Maps the SSZ commitment of the sync committee's pubkeys to a SNARK friendly
 * one using the Poseidon hash function. This is done once every sync committee
 * period to reduce the number of constraints (~70M) in the LightClientUpdate
 * circuit. Called by updateNextSyncCommittee() in the light client.
 *
 * @input  pubkeyBytes             The sync committee pubkeys in bytes
 * @input  aggregatePubkeyBytes    The aggregate sync committee pubkey in bytes
 * @input  pubkeysBigInt           The sync committee pubkeys in bigint
 * @input  aggregatePubkeyBigInt   The aggregate sync committee pubkey in bigint
 * @output syncCommitteeSSZ        A SSZ commitment to the sync committee
 * @output syncCommitteePoseidon   A Poseidon commitment ot the sync committee
 */
template Rotate() {
    var N = getNumBitsPerRegister();
    var K = getNumRegisters();
    var SYNC_COMMITTEE_SIZE = getSyncCommitteeSize();
    var SYNC_COMMITTEE_DEPTH = getSyncCommitteeDepth();
    var SYNC_COMMITTEE_INDEX = getSyncCommitteeIndex();
    var G1_POINT_SIZE = getG1PointSize();

    /* Sync Commmittee */
    signal input pubkeysBytes[SYNC_COMMITTEE_SIZE][48];
    signal input aggregatePubkeyBytes[48];
    signal input pubkeysBigInt[SYNC_COMMITTEE_SIZE][2][K];
    signal input aggregatePubkeyBigInt[2][K];
    signal input syncCommitteeSSZ[32];
    signal input syncCommitteeBranch[SYNC_COMMITTEE_DEPTH][32];

    /* Finalized Header */
    signal input finalizedHeaderRoot[32];
    signal input finalizedSlot[32];
    signal input finalizedProposerIndex[32];
    signal input finalizedParentRoot[32];
    signal input finalizedStateRoot[32];
    signal input finalizedBodyRoot[32];

    /* Sync Committee */
    signal input syncCommitteePoseidon;

    /* VALIDATE FINALIZED HEADER AGAINST FINALIZED HEADER ROOT */
    component sszFinalizedHeader = SSZPhase0BeaconBlockHeader();
    for (var i = 0; i < 32; i++) {
        sszFinalizedHeader.slot[i] <== finalizedSlot[i];
        sszFinalizedHeader.proposerIndex[i] <== finalizedProposerIndex[i];
        sszFinalizedHeader.parentRoot[i] <== finalizedParentRoot[i];
        sszFinalizedHeader.stateRoot[i] <== finalizedStateRoot[i];
        sszFinalizedHeader.bodyRoot[i] <== finalizedBodyRoot[i];
    }
    for (var i = 0; i < 32; i++) {
        sszFinalizedHeader.out[i] === finalizedHeaderRoot[i];
    }

    /* CHECK SYNC COMMITTEE SSZ PROOF */
    component verifySyncCommittee = SSZRestoreMerkleRoot(
        SYNC_COMMITTEE_DEPTH,
        SYNC_COMMITTEE_INDEX
    );
    for (var i = 0; i < 32; i++) {
        verifySyncCommittee.leaf[i] <== syncCommitteeSSZ[i];
        for (var j = 0; j < SYNC_COMMITTEE_DEPTH; j++) {
            verifySyncCommittee.branch[j][i] <== syncCommitteeBranch[j][i];
        }
    }
    for (var i = 0; i < 32; i++) {
        verifySyncCommittee.out[i] === finalizedStateRoot[i];
    }

    /* MAKE SURE BYTE AND BIG INT REPRESENTATION OF G1 POINTS MATCH */
    component g1BytesToBigInt[SYNC_COMMITTEE_SIZE+1];
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        g1BytesToBigInt[i] = G1BytesToBigInt(N, K, G1_POINT_SIZE);
        for (var j = 0; j < 48; j++) {
            g1BytesToBigInt[i].in[j] <== pubkeysBytes[i][j];
        }
        for (var j = 0; j < K; j++) {
            g1BytesToBigInt[i].out[j] === pubkeysBigInt[i][0][j];
        }
    }
    var aggregateKeyIdx = SYNC_COMMITTEE_SIZE;
    g1BytesToBigInt[aggregateKeyIdx] = G1BytesToBigInt(N, K, G1_POINT_SIZE);
    for (var i = 0; i < 48; i++) {
        g1BytesToBigInt[aggregateKeyIdx].in[i] <== aggregatePubkeyBytes[i];
    }
    for (var i = 0; i < K; i++) {
        g1BytesToBigInt[aggregateKeyIdx].out[i] === aggregatePubkeyBigInt[0][i];
    }

    /* VERIFY THE SSZ ROOT OF THE SYNC COMMITTEE */
    component sszSyncCommittee = SSZPhase0SyncCommittee();
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        for (var j = 0; j < 48; j++) {
            sszSyncCommittee.pubkeys[i][j] <== pubkeysBytes[i][j];
        }
    }
    for (var i = 0; i < 48; i++) {
        sszSyncCommittee.aggregatePubkey[i] <== aggregatePubkeyBytes[i];
    }
    for (var i = 0; i < 32; i++) {
        syncCommitteeSSZ[i] === sszSyncCommittee.out[i];
    }

    /* VERIFY THE POSEIDON ROOT OF THE SYNC COMMITTEE */
    component computePoseidonRoot = PoseidonG1Array(
        SYNC_COMMITTEE_SIZE,
        N,
        K
    );
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        for (var j = 0; j < K; j++) {
            computePoseidonRoot.pubkeys[i][0][j] <== pubkeysBigInt[i][0][j];
            computePoseidonRoot.pubkeys[i][1][j] <== pubkeysBigInt[i][1][j];
        }
    }
    syncCommitteePoseidon === computePoseidonRoot.out;
}

component main {public [finalizedHeaderRoot, syncCommitteeSSZ, syncCommitteePoseidon]} = Rotate();