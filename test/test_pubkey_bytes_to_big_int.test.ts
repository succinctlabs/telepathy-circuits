import fs from 'fs';
import path from 'path';

import { PointG1, utils } from '@noble/bls12-381';
import { expect, assert } from 'chai';

import { hexToIntArray, bigint_to_array, point_to_bigint } from './bls_utils';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

(BigInt.prototype as any).toJSON = function () {
    return this.toString();
};

const n = 55;
const k = 7;

describe('BLS12-381-PubkeyBytesToBigInt', function () {
    jest.setTimeout(1000 * 1000);

    // runs circom compilation
    let circuit: any;
    beforeEach(async function () {
        circuit = await wasm_tester(
            path.join(__dirname, 'circuits', 'test_pubkey_bytes_to_big_int.circom')
        );
    });

    it('Should test a pubkey', async function () {
        const publicKeyHex =
            '0x891e60aff6ac35f971ce1536e6338f92c0f090415906e4097b35d1956b443d111da1d8839f35b598d92b233594d49762';
        const publicKey = PointG1.fromHex(publicKeyHex.slice(2));
        const x = point_to_bigint(publicKey)[0];

        const pubkeyBytesInput = hexToIntArray(publicKeyHex);

        const witnessInput = {
            in: pubkeyBytesInput
        };

        const witness = await circuit.calculateWitness(witnessInput);
        await circuit.assertOut(witness, { out: bigint_to_array(n, k, x) });
        await circuit.checkConstraints(witness);
    });

    for (let i = 0; i < 16; i++) {
        it(`Should test random pubkeys attempt ${i + 1}`, async function () {
            const publicKeyHex = PointG1.fromPrivateKey(utils.randomPrivateKey()).toHex(true);
            const publicKey = PointG1.fromHex(publicKeyHex);
            const x = point_to_bigint(publicKey)[0];

            const pubkeyBytesInput = hexToIntArray(publicKeyHex);

            const witnessInput = {
                in: pubkeyBytesInput
            };

            const witness = await circuit.calculateWitness(witnessInput);
            await circuit.assertOut(witness, { out: bigint_to_array(n, k, x) });
            await circuit.checkConstraints(witness);
        });
    }
});
