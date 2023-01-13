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

describe('BLS12-381-AggregateAdd', function () {
    jest.setTimeout(1000 * 1000);

    let circuit: any;
    beforeAll(async function () {
        circuit = await wasm_tester(
            path.join(__dirname, 'circuits', 'test_aggregate_bls_add_4.circom')
        );
    });

    const test_cases: Array<
        [
            [bigint, bigint],
            [bigint, bigint],
            [bigint, bigint],
            [bigint, bigint],
            [bigint, bigint],
            number[]
        ]
    > = [];

    for (let test = 1; test < 16; test++) {
        const bitArray = test
            .toString(2)
            .padStart(4, '0')
            .split('')
            .map((x) => parseInt(x));
        const pubkeys: Array<PointG1> = [];
        let sum = PointG1.ZERO;
        for (let idx = 0; idx < 4; idx++) {
            const pubkey: PointG1 = PointG1.fromPrivateKey(BigInt(private_keys[idx]));
            pubkeys.push(pubkey);
            if (bitArray[idx] == 1) {
                sum = sum.add(pubkey);
            }
        }
        test_cases.push([
            point_to_bigint(pubkeys[0]),
            point_to_bigint(pubkeys[1]),
            point_to_bigint(pubkeys[2]),
            point_to_bigint(pubkeys[3]),
            point_to_bigint(sum),
            bitArray
        ]);
    }

    const test_bls12381_add_instance = function (
        test_case: [
            [bigint, bigint],
            [bigint, bigint],
            [bigint, bigint],
            [bigint, bigint],
            [bigint, bigint],
            number[]
        ]
    ) {
        const [pub0x, pub0y] = test_case[0];
        const [pub1x, pub1y] = test_case[1];
        const [pub2x, pub2y] = test_case[2];
        const [pub3x, pub3y] = test_case[3];
        const [sumAllx, sumAlly] = test_case[4];
        const bitArray = test_case[5];

        const n = 55;
        const k = 7;
        const pub0x_array: bigint[] = bigint_to_array(n, k, pub0x);
        const pub0y_array: bigint[] = bigint_to_array(n, k, pub0y);
        const pub1x_array: bigint[] = bigint_to_array(n, k, pub1x);
        const pub1y_array: bigint[] = bigint_to_array(n, k, pub1y);

        it(JSON.stringify(bitArray), async function () {
            const witness = await circuit.calculateWitness({
                pubkeys: [
                    [pub0x_array, pub0y_array],
                    [pub1x_array, pub1y_array],
                    [bigint_to_array(n, k, pub2x), bigint_to_array(n, k, pub2y)],
                    [bigint_to_array(n, k, pub3x), bigint_to_array(n, k, pub3y)]
                ],
                bits: bitArray
            });
            await circuit.assertOut(witness, {
                out: [bigint_to_array(n, k, sumAllx), bigint_to_array(n, k, sumAlly)]
            });
            await circuit.checkConstraints(witness);
        });
    };

    test_cases.forEach(test_bls12381_add_instance);
});
