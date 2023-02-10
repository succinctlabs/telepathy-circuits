/*
  noble-bls12-381 - MIT License (c) 2019 Paul Miller (paulmillr.com)
  This file is used to generate test cases for circuits that use functions related to the BLS12-381 curve.
  The original source file is from: https://github.com/paulmillr/noble-bls12-381/blob/main/index.ts.
*/

// bls12-381 is a construction of two curves:
// 1. Fp: (x, y)
// 2. Fp₂: ((x₁, x₂+i), (y₁, y₂+i)) - (complex numbers)
//
// Bilinear Pairing (ate pairing) is used to combine both elements into a paired one:
//   Fp₁₂ = e(Fp, Fp2)
//   where Fp₁₂ = 12-degree polynomial
// Pairing is used to verify signatures.
//
// We are using Fp for private keys (shorter) and Fp2 for signatures (longer).
// Some projects may prefer to swap this relation, it is not supported for now.

import { PointG1, utils } from '@noble/bls12-381';

function formatHex(str: string): string {
    if (str.startsWith('0x')) {
        str = str.slice(2);
    }
    return str;
}

export function hexToIntArray(hex: string): bigint[] {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    hex = formatHex(hex);
    if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
    const array = [];
    for (let i = 0; i < hex.length / 2; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        if (hexByte.length !== 2) throw new Error('Invalid byte sequence');
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0) {
            console.log(hexByte, byte);
            throw new Error('Invalid byte sequence');
        }
        array.push(BigInt(byte));
    }
    return array;
}

export function point_to_bigint(point: PointG1): [bigint, bigint] {
    const [x, y] = point.toAffine();
    return [x.value, y.value];
}

export function bigint_to_array(n: number, k: number, x: bigint) {
    let mod = 1n;
    for (let idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    const ret: string[] = [];
    let x_temp: bigint = x;
    for (let idx = 0; idx < k; idx++) {
        ret.push((x_temp % mod).toString());
        x_temp = x_temp / mod;
    }
    return ret;
}

export async function msg_hash(
    message: string | Uint8Array,
    returnType: 'array' | 'hex' = 'array'
) {
    let msg;
    if (typeof message === 'string') {
        msg = utils.stringToBytes(message);
    } else {
        msg = message;
    }
    msg = msg as unknown as Uint8Array;

    const u = await utils.hashToField(msg, 2);

    if (returnType === 'hex') {
        return [
            ['0x' + u[0][0].toString(16), '0x' + u[0][1].toString(16)],
            ['0x' + u[1][0].toString(16), '0x' + u[1][1].toString(16)]
        ];
    } else {
        return [
            [bigint_to_array(55, 7, u[0][0]), bigint_to_array(55, 7, u[0][1])],
            [bigint_to_array(55, 7, u[1][0]), bigint_to_array(55, 7, u[1][1])]
        ];
    }
}
