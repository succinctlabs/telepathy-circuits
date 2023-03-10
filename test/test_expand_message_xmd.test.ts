import path from 'path';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

describe('BLS12-381-ExpandMessageXMD', function () {
    jest.setTimeout(1000 * 1000);
    let circuit: any;
    beforeEach(async function () {
        circuit = await wasm_tester(
            path.join(__dirname, 'circuits', 'test_expand_message_xmd.circom')
        );
    });

    it('Uint8Array(johnguibas)', async function () {
        const input = {
            msg: [106, 111, 104, 110, 103, 117, 105, 98, 97, 115],
            dst: [
                66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 95, 88, 77,
                68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95, 80, 79, 80,
                95
            ]
        };
        const output = [
            82, 224, 113, 57, 37, 246, 136, 235, 36, 178, 110, 190, 208, 189, 11, 71, 7, 170, 198,
            244, 57, 211, 106, 126, 51, 185, 192, 154, 175, 245, 15, 180, 57, 196, 186, 148, 56, 88,
            208, 59, 182, 64, 136, 246, 247, 239, 187, 54, 56, 251, 194, 70, 71, 193, 28, 196, 177,
            210, 119, 85, 6, 140, 175, 198, 17, 52, 168, 92, 62, 90, 143, 218, 26, 252, 42, 101, 64,
            44, 86, 218, 127, 230, 39, 169, 26, 118, 74, 210, 177, 16, 167, 58, 56, 48, 105, 37,
            120, 91, 131, 75, 3, 0, 206, 247, 8, 31, 70, 168, 47, 253, 248, 143, 53, 225, 203, 168,
            2, 83, 185, 115, 218, 101, 9, 98, 202, 123, 157, 80, 162, 116, 94, 25, 74, 158, 202, 5,
            199, 165, 78, 51, 200, 114, 227, 96, 210, 207, 38, 60, 62, 249, 135, 248, 114, 6, 117,
            58, 189, 239, 10, 97, 23, 232, 51, 193, 160, 124, 182, 162, 124, 3, 169, 108, 75, 78,
            65, 25, 111, 26, 235, 222, 98, 13, 66, 37, 50, 89, 238, 91, 41, 99, 177, 227, 247, 58,
            191, 51, 234, 233, 92, 57, 175, 157, 105, 8, 90, 101, 122, 139, 146, 34, 141, 228, 99,
            231, 84, 223, 196, 137, 219, 94, 211, 142, 152, 179, 82, 139, 156, 176, 96, 45, 113,
            231, 235, 183, 84, 216, 244, 34, 38, 209, 23, 153, 77, 101, 102, 242, 118, 79, 124, 94,
            226, 190, 21, 107, 225, 65
        ];
        const witness = await circuit.calculateWitness(input);
        for (let i = 0; i < 256; i++) {
            expect(witness[i + 1]).toBe(BigInt(output[i]));
        }
        await circuit.checkConstraints(witness);
    });

    it('Uint8Array(abcdefghij)', async function () {
        const input = {
            msg: [97, 98, 99, 100, 101, 102, 103, 104, 105, 106],
            dst: [
                66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 95, 88, 77,
                68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95, 80, 79, 80,
                95
            ]
        };
        const output = [
            114, 119, 3, 107, 108, 37, 184, 47, 36, 94, 86, 170, 250, 62, 201, 56, 159, 156, 77, 7,
            130, 66, 104, 218, 240, 189, 255, 180, 115, 152, 31, 98, 208, 114, 244, 153, 26, 6, 116,
            172, 25, 211, 196, 140, 229, 217, 102, 253, 160, 152, 0, 53, 195, 26, 37, 195, 10, 141,
            133, 212, 85, 32, 56, 192, 243, 233, 4, 231, 56, 121, 58, 92, 42, 60, 231, 160, 214,
            201, 96, 214, 88, 203, 182, 178, 8, 149, 222, 116, 176, 12, 113, 215, 214, 241, 225, 52,
            53, 204, 200, 34, 78, 123, 252, 132, 38, 42, 251, 182, 24, 0, 175, 40, 198, 12, 31, 152,
            151, 239, 175, 66, 236, 158, 246, 94, 227, 28, 112, 75, 253, 25, 249, 9, 245, 219, 85,
            75, 143, 129, 79, 57, 108, 226, 74, 125, 34, 16, 128, 39, 213, 74, 30, 168, 137, 226,
            115, 179, 82, 52, 232, 68, 89, 239, 75, 16, 123, 239, 20, 52, 230, 110, 116, 19, 69,
            135, 47, 20, 56, 103, 19, 48, 213, 221, 30, 164, 173, 118, 58, 138, 241, 232, 249, 61,
            77, 101, 151, 157, 98, 156, 250, 247, 195, 53, 153, 184, 107, 228, 115, 208, 95, 11,
            166, 76, 117, 18, 9, 32, 60, 179, 17, 220, 94, 6, 184, 148, 59, 149, 163, 75, 97, 218,
            8, 44, 232, 116, 227, 213, 10, 156, 136, 77, 116, 124, 145, 204, 168, 178, 50, 153, 209,
            196, 45, 72, 220, 134, 105, 22
        ];
        const witness = await circuit.calculateWitness(input);
        for (let i = 0; i < 256; i++) {
            expect(witness[i + 1]).toBe(BigInt(output[i]));
        }
        await circuit.checkConstraints(witness);
    });
});
