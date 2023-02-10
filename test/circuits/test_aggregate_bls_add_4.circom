pragma circom 2.0.5;

include "../../circuits/bls.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../circuits/pairing/fp.circom";
include "../../circuits/pairing/field_elements_func.circom";
include "../../circuits/constants.circom";

component main {public [pubkeys, bits]} = G1AddMany(4, 2, 55, 7);