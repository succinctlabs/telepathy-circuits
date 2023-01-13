pragma circom 2.0.5;

include "../../circuits/bls.circom";
include "../../circuits/constants.circom";

component main {public [in]} = G1BytesToBigInt(55, 7, 48);