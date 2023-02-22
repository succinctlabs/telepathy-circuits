pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/*
 * Helper functions for computing Poseidon commitments to the sync committee's
 * validator public keys.
 */

template PoseidonG1Array(LENGTH, N, K) {
    signal input pubkeys[LENGTH][2][K];
    signal output out;

    component hasher = PoseidonSponge(LENGTH * 2 * K);
    for (var i = 0; i < LENGTH; i++) {
        for (var j = 0; j < K; j++) {
            for (var l = 0; l < 2; l++) {
                hasher.in[(i * K * 2) + (j * 2) + l] <== pubkeys[i][l][j];
            }
        }
    }
    out <== hasher.out;
}


template PoseidonSponge(LENGTH) {
    assert(LENGTH % 16 == 0);
    signal input in[LENGTH];
    signal output out;

    var POSEIDON_SIZE = 16;
    var NUM_ROUNDS = LENGTH \ POSEIDON_SIZE;

    component hashers[NUM_ROUNDS];
    for (var i = 0; i < NUM_ROUNDS; i++) {
        if (i < NUM_ROUNDS - 1) {
            hashers[i] = PoseidonEx(POSEIDON_SIZE, 1);
        } else {
            hashers[i] = PoseidonEx(POSEIDON_SIZE, 2);
        }
        for (var j = 0; j < POSEIDON_SIZE; j++) {
            hashers[i].inputs[j] <== in[i*POSEIDON_SIZE+j];
        }

        if (i == 0) {
            hashers[i].initialState <== 0;
        } else {
            hashers[i].initialState <== hashers[i-1].out[0];
        }
    }

    out <== hashers[NUM_ROUNDS-1].out[1];
}