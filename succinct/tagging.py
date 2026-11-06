"""
Tagging scheme (§6.1.1).

    TagKGen(x) = G^x      one-time public key
    TagEval(x) = U^x      key image ("tag")

Same secret, two bases. Spending the same coin twice reproduces the same tag,
which is how double spends are caught. Telling whether a given tag belongs to a
given public key is a DDH problem, which is why tags don't reveal the spender.

TagKGen is additively homomorphic: TagKGen(x1) + TagKGen(x2) = TagKGen(x1 + x2).
stealth.py relies on that to evaluate a polynomial "in the exponent".
"""

from .group import G, U


def tag_kgen(x):
    return x * G


def tag_eval(x):
    return x * U
