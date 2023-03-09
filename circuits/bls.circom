pragma circom 2.0.5;

include "./pairing/bls_signature.circom";
include "./pairing/curve.circom";
include "./pairing/bls12_381_func.circom";
include "./sha256.circom";

/*
 * This file efficiently implements BLS12-381 public key aggregation. It takes
 * advantage of parallel witness generation to compute the aggregate in a 
 * "MapReduce" like manner. In particular, it starts off with some power of two
 * G1 points to aggregate and reduces it to half the size. It repeats this
 * procedure until there is only one G1 point left.
 */

template G1AddMany(SYNC_COMMITTEE_SIZE, LOG_2_SYNC_COMMITTEE_SIZE, N, K) {
    // It is assumed that none of the input signals are ill-formed. The public
    // keys are checked such that they are all properly reduced and less than
    // the prime of the base field. The bits are assumed to be range checked
    // such that the only possible values are 0 or 1.
    signal input pubkeys[SYNC_COMMITTEE_SIZE][2][K];
    signal input bits[SYNC_COMMITTEE_SIZE];
    signal output out[2][K];
    signal output isPointAtInfinity;

    component reducers[LOG_2_SYNC_COMMITTEE_SIZE];
    for (var i = 0; i < LOG_2_SYNC_COMMITTEE_SIZE; i++) {
        var BATCH_SIZE = SYNC_COMMITTEE_SIZE \ (2 ** i);
        reducers[i] = G1Reduce(BATCH_SIZE, N, K);
        for (var j = 0; j < BATCH_SIZE; j++) {
            if (i == 0) {
                reducers[i].bits[j] <== bits[j];
            } else {
                reducers[i].bits[j] <== reducers[i-1].outBits[j];
            }
            for (var q = 0; q < K; q++) {
                if (i == 0) {
                    reducers[i].pubkeys[j][0][q] <== pubkeys[j][0][q];
                    reducers[i].pubkeys[j][1][q] <== pubkeys[j][1][q];
                } else {
                    reducers[i].pubkeys[j][0][q] <== reducers[i-1].out[j][0][q];
                    reducers[i].pubkeys[j][1][q] <== reducers[i-1].out[j][1][q];
                }
            }
        }
    }

    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < K; j++) {
            out[i][j] <== reducers[LOG_2_SYNC_COMMITTEE_SIZE-1].out[0][i][j];
        }
    }
    isPointAtInfinity <== 1 - reducers[LOG_2_SYNC_COMMITTEE_SIZE-1].outBits[0];
}


template G1Reduce(BATCH_SIZE, N, K) {
    var OUTPUT_BATCH_SIZE = BATCH_SIZE \ 2;
    signal input pubkeys[BATCH_SIZE][2][K];
    signal input bits[BATCH_SIZE];
    signal output out[OUTPUT_BATCH_SIZE][2][K];
    signal output outBits[OUTPUT_BATCH_SIZE];

    component adders[OUTPUT_BATCH_SIZE];
    for (var i = 0; i < OUTPUT_BATCH_SIZE; i++) {
        adders[i] = G1Add(N, K);
        adders[i].bit1 <== bits[i * 2];
        adders[i].bit2 <== bits[i * 2 + 1];
        for (var j = 0; j < 2; j++) {
            for (var l = 0; l < K; l++) {
                adders[i].pubkey1[j][l] <== pubkeys[i * 2][j][l];
                adders[i].pubkey2[j][l] <== pubkeys[i * 2 + 1][j][l];
            }
        }
    }

    for (var i = 0; i < OUTPUT_BATCH_SIZE; i++) {
        outBits[i] <== adders[i].outBit;
        for (var j = 0; j < 2; j++) {
            for (var l = 0; l < K; l++) {
                out[i][j][l] <== adders[i].out[j][l];
            }
        }
    }
}


template parallel G1Add(N, K) {
    var A1 = getCurveA1();
    var B1 = getCurveB1();
    var P[7] = getBLS128381Prime();
    
    signal input pubkey1[2][K];
    signal input pubkey2[2][K];
    signal input bit1;
    signal input bit2;

    signal output out[2][K];
    signal output outBit;

    component adder = EllipticCurveAdd(N, K, A1, B1, P);
    adder.aIsInfinity <== 1 - bit1;
    adder.bIsInfinity <== 1 - bit2;
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < K; j++) {
            adder.a[i][j] <== pubkey1[i][j];
            adder.b[i][j] <== pubkey2[i][j];
        }
    }

    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < K; j++) {
            out[i][j] <== adder.out[i][j];
        }
    }
    outBit <== 1 - adder.isInfinity;
    outBit * (outBit - 1) === 0;
}


template G1BytesToBigInt(N, K, G1_POINT_SIZE) {
    assert(G1_POINT_SIZE == 48);
    signal input in[G1_POINT_SIZE];
    signal output out[K];

    component bitifiers[G1_POINT_SIZE];
    for (var i=0; i < G1_POINT_SIZE; i++) {
        bitifiers[i] = Num2Bits(8);
        bitifiers[i].in <== in[i];
    }

    signal pubkeyBits[G1_POINT_SIZE * 8];
    for (var i = G1_POINT_SIZE - 1; i >= 0; i--) {
        for (var j = 0; j < 8; j++) {
            pubkeyBits[(G1_POINT_SIZE - 1 - i) * 8 + j] <== bitifiers[i].out[j];
        }
    }

    component convertBitsToBigInt[K];
    for (var i = 0; i < K; i++) {
        convertBitsToBigInt[i] = Bits2Num(N);
        for (var j = 0; j < N; j++) {
            if (i * N + j >= G1_POINT_SIZE * 8 || i * N + j >= 381) {
                convertBitsToBigInt[i].in[j] <== 0;
            } else {
                convertBitsToBigInt[i].in[j] <== pubkeyBits[i * N + j];
            }
        }
    }

    for (var i = 0; i < K; i++) {
        out[i] <== convertBitsToBigInt[i].out;
    }

    // We check this bit is not 0 to make sure the point is not zero.
    // Reference: https://github.com/paulmillr/noble-bls12-381/blob/main/index.ts#L306
    pubkeyBits[382] === 0;
}


template G1BytesToSignFlag(N, K, G1_POINT_SIZE) {
    signal input in[G1_POINT_SIZE];
    signal output out;

    component bitifiers[G1_POINT_SIZE];
    for (var i=0; i < G1_POINT_SIZE; i++) {
        bitifiers[i] = Num2Bits(8);
        bitifiers[i].in <== in[i];
    }

    signal pubkeyBits[G1_POINT_SIZE * 8];
    for (var i = G1_POINT_SIZE - 1; i >= 0; i--) {
        for (var j = 0; j < 8; j++) {
            pubkeyBits[(G1_POINT_SIZE - 1 - i) * 8 + j] <== bitifiers[i].out[j];
        }
    }    

    // We extract the sign flag to know whether the completed point is y or -y.
    // Reference: https://github.com/paulmillr/noble-bls12-381/blob/main/index.ts#L313
    out <== pubkeyBits[381];
}


template G1BigIntToSignFlag(N, K) {
    signal input in[K];
    signal output out;

    var P[K] = getBLS128381Prime();
    var LOG_K = log_ceil(K);
    component mul = BigMult(N, K);

    signal two[K];
    for (var i = 0; i < K; i++) {
        if (i == 0) {
            two[i] <== 2;
        } else {
            two[i] <== 0;
        }
    }

    for (var i = 0; i < K; i++) {
        mul.a[i] <== in[i];
        mul.b[i] <== two[i];
    }

    component lt = BigLessThan(N, K);
    for (var i = 0; i < K; i++) {
        lt.a[i] <== mul.out[i];
        lt.b[i] <== P[i];
    }

    out <== 1 - lt.out;
}