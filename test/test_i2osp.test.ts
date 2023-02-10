import path from 'path';

import { utils } from '@noble/bls12-381';
import { expect } from 'chai';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester');

const wasm_tester = circom_tester.wasm;

describe('i2osp-1', function () {
    jest.setTimeout(1000 * 1000);

    let circuit: any;
    beforeAll(async function () {
        circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_i2osp_1.circom'));
    });

    // witness[0] is whether it succeed or not (boolean)
    // witness[1] ... witness[n] is your output bytes

    it('i2osp(DST.length, 1)', async function () {
        const witnessInput = { in: utils.htfDefaults.DST.length };
        const witness = await circuit.calculateWitness(witnessInput);
        const expectedOutput = utils.i2osp(witnessInput.in, 1);
        expect(witness[1]).to.equal(BigInt(expectedOutput[0]));
        await circuit.checkConstraints(witness);
    });

    it('i2osp(0, 1)', async function () {
        const witnessInput = { in: 0 };
        const witness = await circuit.calculateWitness(witnessInput);
        const expectedOutput = utils.i2osp(witnessInput.in, 1);
        expect(witness[1]).to.equal(BigInt(expectedOutput[0]));
        await circuit.checkConstraints(witness);
    });

    it('i2osp(1, 1)', async function () {
        const witnessInput = { in: 1 };
        const witness = await circuit.calculateWitness(witnessInput);
        const expectedOutput = utils.i2osp(witnessInput.in, 1);
        expect(witness[1]).to.equal(BigInt(expectedOutput[0]));
        await circuit.checkConstraints(witness);
    });
});

describe('i2osp-2', function () {
    jest.setTimeout(1000 * 1000);
    let circuit: any;
    beforeAll(async function () {
        circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_i2osp_2.circom'));
    });

    it('i2osp(8, 2)', async function () {
        const witnessInput = { in: 8 };
        const witness = await circuit.calculateWitness(witnessInput);
        const expectedOutput = utils.i2osp(witnessInput.in, 2);
        expect(witness[1]).to.equal(BigInt(expectedOutput[0]));
        expect(witness[2]).to.equal(BigInt(expectedOutput[1]));
        await circuit.checkConstraints(witness);
    });

    it('i2osp(89, 2)', async function () {
        const witnessInput = { in: 89 };
        const witness = await circuit.calculateWitness(witnessInput);
        const expectedOutput = utils.i2osp(witnessInput.in, 2);
        expect(witness[1]).to.equal(BigInt(expectedOutput[0]));
        expect(witness[2]).to.equal(BigInt(expectedOutput[1]));
        await circuit.checkConstraints(witness);
    });
});
