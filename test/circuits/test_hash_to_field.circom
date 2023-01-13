pragma circom 2.0.5;

include "../../circuits/hash_to_field.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../circuits/pairing/fp.circom";
include "../../circuits/pairing/field_elements_func.circom";
include "../../circuits/constants.circom";

component main {public [msg]} = HashToField(10, 2);