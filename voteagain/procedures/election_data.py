from petlib.ec import Bn
import numpy as np

from voteagain.primitives.ballot_structure import BallotBundle, VoteVector

import voteagain.primitives.ballot_structure as ballot_structure
import voteagain.primitives.elgamal as elgamal


def generate_ciphertexts(number_ciphertexts, G, pk):
    """
    Generate 'number_ciphertexts' number of ciphertexts in group G with public
    key pk, and the corresponding randomizers for a random permutation
    """

    plaintext = G.infinite()
    ctxts = []
    vote = ballot_structure.VoteVector([pk.encrypt(1 * G.generator())])
    for i in range(number_ciphertexts):
        ctxts.append(
            ballot_structure.BallotBundle(
                pk.encrypt(plaintext),
                pk.encrypt(plaintext),
                pk.encrypt(plaintext),
                vote,
            )
        )

    return ctxts


def generate_shuffled_reencryptions(ctxts, permutation, G, pk, values_vector=True):
    randomizers = []
    shuffled_ctxts = []
    if values_vector:
        for i in range(len(ctxts)):
            randomizers.append(
                ballot_structure.ValuesVector(
                    G.order().random(),
                    G.order().random(),
                    G.order().random(),
                    G.order().random(),
                )
            )
    else:
        for i in range(len(ctxts)):
            randomizers.append(G.order().random())
    for index, permuted_index in enumerate(permutation):
        shuffled_ctxts.append(
            pk.reencrypt(ctxts[permuted_index], ephemeral_key=randomizers[index])
        )
    return randomizers, shuffled_ctxts


def election_setup(group, number_voters, security_param):
    order = group.order()
    counter_space = Bn.from_num(2).pow(security_param - 2)
    vids = []
    counter = []
    for i in range(number_voters):
        vids.append(order.random())
        index = counter_space + counter_space.random()
        counter.append(index)

    return vids, counter


def generate_ballots(pk, vids, counters, single_vote=True, revotes_fraction=0.0):
    G = pk.group
    infinity = pk.group.infinite()

    lookup_table = {}
    lookup_table[infinity] = 0

    vote = VoteVector([pk.encrypt(1 * G.generator())])

    ctxts = []
    nr_revotes = 0

    if single_vote:
        for i, vid in enumerate(vids):
            repr = counters[i] * pk.generator
            lookup_table[repr] = counters[i]
            ctxts.append(
                BallotBundle(
                    pk.encrypt(vid * G.generator()),
                    pk.encrypt(counters[i] * G.generator()),
                    elgamal.Ciphertext(infinity, infinity),
                    vote,
                )
            )

    else:
        # Since it doesn't matter, dump all revotes on the first voter
        # voter_revoted = np.random.randint(max_votes_added, size=len(vids))
        voter_revoted = np.zeros(len(vids), dtype=int)
        voter_revoted[0] = round(revotes_fraction * len(vids))
        nr_revotes = sum(voter_revoted)

        for i, vid in enumerate(vids):
            while voter_revoted[i] >= 0:
                repr = counters[i] * pk.generator
                lookup_table[repr] = counters[i]
                ctxts.append(
                    BallotBundle(
                        pk.encrypt(vid * G.generator()),
                        pk.encrypt(counters[i] * G.generator()),
                        elgamal.Ciphertext(infinity, infinity),
                        vote,
                    )
                )
                counters[i] += 1
                voter_revoted[i] -= 1
    return ctxts, lookup_table, nr_revotes
