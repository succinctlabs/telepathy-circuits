pragma circom 2.0.5;

include "../../circuits/pairing/curve.circom";

component main {public [a, aIsInfinity, b, bIsInfinity]} = EllipticCurveAdd(55, 7, 0, 4, [
    35747322042231467,
    36025922209447795,
    1084959616957103,
    7925923977987733,
    16551456537884751,
    23443114579904617,
    1829881462546425
]);