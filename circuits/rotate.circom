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
 * period to reduce the number of constraints (~70M) in the Step circuit. Called by rotate()
 * in the light client.
 *
 * @input  pubkeyBytes             The sync committee pubkeys in bytes
 * @input  aggregatePubkeyBytesX   The aggregate sync committee pubkey in bytes
 * @input  pubkeysBigInt           The sync committee pubkeys in bigint
 * @input  syncCommitteeSSZ        A SSZ commitment to the sync committee
 * @input  syncCommitteeBranch     A Merkle proof for the sync committee against finalizedHeader
 * @input  syncCommitteePoseidon   A Poseidon commitment ot the sync committee
 * @input  finalizedHeader         The finalized header which provides the next sync committee
 */
template Rotate() {
    var N = getNumBitsPerRegister();
    var K = getNumRegisters();
    var SYNC_COMMITTEE_SIZE = getSyncCommitteeSize();
    var LOG_2_SYNC_COMMITTEE_SIZE = getLog2SyncCommitteeSize();
    var SYNC_COMMITTEE_DEPTH = getSyncCommitteeDepth();
    var SYNC_COMMITTEE_INDEX = getSyncCommitteeIndex();
    var G1_POINT_SIZE = getG1PointSize();
    var P[K] = getBLS128381Prime();

    /* Sync Commmittee */
    signal input pubkeysBytes[SYNC_COMMITTEE_SIZE][G1_POINT_SIZE];
    signal input aggregatePubkeyBytesX[G1_POINT_SIZE];
    signal input pubkeysBigIntX[SYNC_COMMITTEE_SIZE][K];
    signal input pubkeysBigIntY[SYNC_COMMITTEE_SIZE][K];
    signal input syncCommitteeSSZ[32];
    signal input syncCommitteeBranch[SYNC_COMMITTEE_DEPTH][32];
    signal input syncCommitteePoseidon;

    /* Finalized Header */
    signal input finalizedHeaderRoot[32];
    signal input finalizedSlot[32];
    signal input finalizedProposerIndex[32];
    signal input finalizedParentRoot[32];
    signal input finalizedStateRoot[32];
    signal input finalizedBodyRoot[32];

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

    /* VERIFY PUBKEY BIGINTS ARE NOT ILL-FORMED */
    component pubkeyReducedChecksX[SYNC_COMMITTEE_SIZE];
    component pubkeyReducedChecksY[SYNC_COMMITTEE_SIZE];
    component pubkeyRangeChecksX[SYNC_COMMITTEE_SIZE][K];
    component pubkeyRangeChecksY[SYNC_COMMITTEE_SIZE][K];
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        pubkeyReducedChecksX[i] = BigLessThan(N, K);
        pubkeyReducedChecksY[i] = BigLessThan(N, K);
        for (var j = 0; j < K; j++) {
            pubkeyReducedChecksX[i].a[j] <== pubkeysBigIntX[i][j];
            pubkeyReducedChecksX[i].b[j] <== P[j];
            pubkeyReducedChecksY[i].a[j] <== pubkeysBigIntY[i][j];
            pubkeyReducedChecksY[i].b[j] <== P[j];
            pubkeyRangeChecksX[i][j] = Num2Bits(N);
            pubkeyRangeChecksX[i][j].in <== pubkeysBigIntX[i][j];
            pubkeyRangeChecksY[i][j] = Num2Bits(N);
            pubkeyRangeChecksY[i][j].in <== pubkeysBigIntY[i][j];
        }
        pubkeyReducedChecksX[i].out === 1;
        pubkeyReducedChecksY[i].out === 1;
    }

    /* VERIFY BYTE AND BIG INT REPRESENTATION OF G1 POINTS MATCH */
    component g1BytesToBigInt[SYNC_COMMITTEE_SIZE];
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        g1BytesToBigInt[i] = G1BytesToBigInt(N, K, G1_POINT_SIZE);
        for (var j = 0; j < 48; j++) {
            g1BytesToBigInt[i].in[j] <== pubkeysBytes[i][j];
        }
        for (var j = 0; j < K; j++) {
            g1BytesToBigInt[i].out[j] === pubkeysBigIntX[i][j];
        }
    }

    /* VERIFY THAT THE WITNESSED Y-COORDINATES MAKE THE PUBKEYS LAY ON THE CURVE */
    component verifyPointOnCurve[SYNC_COMMITTEE_SIZE];
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        verifyPointOnCurve[i] = PointOnBLSCurve(N, K);
        for (var j = 0; j < K; j++) {
            verifyPointOnCurve[i].in[0][j] <== pubkeysBigIntX[i][j];
            verifyPointOnCurve[i].in[1][j] <== pubkeysBigIntY[i][j];
        }
    }

    /* VERIFY THAT THE WITNESSESED Y-COORDINATE HAS THE CORRECT SIGN */
    component bytesToSignFlag[SYNC_COMMITTEE_SIZE];
    component bigIntToSignFlag[SYNC_COMMITTEE_SIZE];
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        bytesToSignFlag[i] = G1BytesToSignFlag(N, K, G1_POINT_SIZE);
        bigIntToSignFlag[i] = G1BigIntToSignFlag(N, K);
        for (var j = 0; j < G1_POINT_SIZE; j++) {
            bytesToSignFlag[i].in[j] <== pubkeysBytes[i][j];
        }
        for (var j = 0; j < K; j++) {
            bigIntToSignFlag[i].in[j] <== pubkeysBigIntY[i][j];
        }
        bytesToSignFlag[i].out === bigIntToSignFlag[i].out;
    }

    /* VERIFY THE SSZ ROOT OF THE SYNC COMMITTEE */
    component sszSyncCommittee = SSZPhase0SyncCommittee(
        SYNC_COMMITTEE_SIZE,
        LOG_2_SYNC_COMMITTEE_SIZE,
        G1_POINT_SIZE
    );
    for (var i = 0; i < SYNC_COMMITTEE_SIZE; i++) {
        for (var j = 0; j < 48; j++) {
            sszSyncCommittee.pubkeys[i][j] <== pubkeysBytes[i][j];
        }
    }
    for (var i = 0; i < 48; i++) {
        sszSyncCommittee.aggregatePubkey[i] <== aggregatePubkeyBytesX[i];
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
            computePoseidonRoot.pubkeys[i][0][j] <== pubkeysBigIntX[i][j];
            computePoseidonRoot.pubkeys[i][1][j] <== pubkeysBigIntY[i][j];
        }
    }
    syncCommitteePoseidon === computePoseidonRoot.out;
}

component main {public [finalizedHeaderRoot, syncCommitteeSSZ, syncCommitteePoseidon]} = Rotate();