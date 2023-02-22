import path from 'path';

import { PointG1 } from '@noble/bls12-381';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

function bigint_to_array(n: number, k: number, x: bigint) {
    let mod = 1n;
    for (let idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    const ret: bigint[] = [];
    let x_temp: bigint = x;
    for (let idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

function point_to_bigint(point: PointG1): [bigint, bigint] {
    const [x, y] = point.toAffine();
    return [x.value, y.value];
}

const private_keys = [
    '0x06a680317cbb1cf70c700b672e48ed01fe5fd51427808a96e17611506e13aed9',
    '0x432bcfbda728fd60570db9505d0b899a9c7c8971ec0fd58252d8028ac0aa76ce',
    '0x6688391de4d32b5779ff669fb72f81b9aaff44e926ba19d5833c5a5c50dd40d2',
    '0x4c24c0c5360b7c44210697a5fba1f705456f37969e1354e30cbd0f290d2efd4a'
];

describe('EllipticCurveAdd', function () {
    jest.setTimeout(1000 * 1000);

    let circuit: any;
    beforeAll(async function () {
        circuit = await wasm_tester(
            path.join(__dirname, 'circuits', 'test_elliptic_curve_add.circom')
        );
    });

    const n = 55;
    const k = 7;

    const pubkeys = private_keys.map((x) => PointG1.fromPrivateKey(BigInt(x)));
    const pubkeysBigIntX = pubkeys.map((x) => point_to_bigint(x)[0]);
    const pubkeysBigIntY = pubkeys.map((x) => point_to_bigint(x)[1]);
    const pubkeysCircomX = pubkeysBigIntX.map((x) => bigint_to_array(n, k, x));
    const pubkeysCircomY = pubkeysBigIntY.map((x) => bigint_to_array(n, k, x));

    it('X + Y, both not infinity', async function () {
        const expected = pubkeys[0].add(pubkeys[1]);
        const expectedBigIntX = point_to_bigint(expected)[0];
        const expectedBigIntY = point_to_bigint(expected)[1];
        const expectedCircomX = bigint_to_array(n, k, expectedBigIntX);
        const expectedCircomY = bigint_to_array(n, k, expectedBigIntY);

        const witness = await circuit.calculateWitness({
            a: [pubkeysCircomX[0], pubkeysCircomY[0]],
            aIsInfinity: 0,
            b: [pubkeysCircomX[1], pubkeysCircomY[1]],
            bIsInfinity: 0
        });
        await circuit.assertOut(witness, {
            out: [expectedCircomX, expectedCircomY],
            isInfinity: 0
        });
        await circuit.checkConstraints(witness);
    });

    it('X + Y, X is infinity', async function () {
        const expected = pubkeys[1];
        const expectedBigIntX = point_to_bigint(expected)[0];
        const expectedBigIntY = point_to_bigint(expected)[1];
        const expectedCircomX = bigint_to_array(n, k, expectedBigIntX);
        const expectedCircomY = bigint_to_array(n, k, expectedBigIntY);

        const witness = await circuit.calculateWitness({
            a: [pubkeysCircomX[0], pubkeysCircomY[0]],
            aIsInfinity: 1,
            b: [pubkeysCircomX[1], pubkeysCircomY[1]],
            bIsInfinity: 0
        });
        await circuit.assertOut(witness, {
            out: [expectedCircomX, expectedCircomY],
            isInfinity: 0
        });
        await circuit.checkConstraints(witness);
    });

    it('X + Y, Y is infinity', async function () {
        const expected = pubkeys[0];
        const expectedBigIntX = point_to_bigint(expected)[0];
        const expectedBigIntY = point_to_bigint(expected)[1];
        const expectedCircomX = bigint_to_array(n, k, expectedBigIntX);
        const expectedCircomY = bigint_to_array(n, k, expectedBigIntY);

        const witness = await circuit.calculateWitness({
            a: [pubkeysCircomX[0], pubkeysCircomY[0]],
            aIsInfinity: 0,
            b: [pubkeysCircomX[1], pubkeysCircomY[1]],
            bIsInfinity: 1
        });
        await circuit.assertOut(witness, {
            out: [expectedCircomX, expectedCircomY],
            isInfinity: 0
        });
        await circuit.checkConstraints(witness);
    });

    it('X + Y, both are infinity', async function () {
        const expected = pubkeys[0];
        const expectedBigIntX = point_to_bigint(expected)[0];
        const expectedBigIntY = point_to_bigint(expected)[1];
        const expectedCircomX = bigint_to_array(n, k, expectedBigIntX);
        const expectedCircomY = bigint_to_array(n, k, expectedBigIntY);

        const witness = await circuit.calculateWitness({
            a: [pubkeysCircomX[0], pubkeysCircomY[0]],
            aIsInfinity: 1,
            b: [pubkeysCircomX[1], pubkeysCircomY[1]],
            bIsInfinity: 1
        });
        await circuit.assertOut(witness, {
            out: [expectedCircomX, expectedCircomY],
            isInfinity: 1
        });
        await circuit.checkConstraints(witness);
    });
});
