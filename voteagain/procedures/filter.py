"""
WARNING: goal is to evaluate running times. The code as written
is not secure.
"""

import time
import numpy as np
import pandas as pd

from petlib.ec import EcGroup, Bn

import voteagain.primitives.pedersen_commitment as commitment
import voteagain.primitives.elgamal as elgamal

from voteagain.primitives.ballot_structure import BallotBundle, VoteVector
from voteagain.dummies.dummies import compute_cover
from voteagain.proofs.efficient_shuffle.shuffle_argument import ShuffleArgument
from voteagain.proofs.correct_reencryption import ReencryptionProof
from voteagain.proofs.correct_decryption import CorrectDecryption


class Filter:
    """
    We follow the steps specified in Lueks, Querejeta-Azurmendi and Troncoso 'VoteAgain: A scalable coercion-resistant
    scheme', of proceedure 5.
    The tally begins once the election is closed, and receives as input the list of all cast ciphertexts.
    We assume that the entry of these values are already the stripped ballots with the tag (without having added the
    dummies yet).

    For simplicity of the experimental code, instead of posting results, we simply make them class variables.
    """

    def __init__(self, kp, voting_key, list_ctxts, m, counter_lookup_table):
        """
        Perform and generate proof of tally
        """
        self.pk = kp.pk
        self.election_key = voting_key
        self.group = kp.group
        self.generator = self.group.generator()
        self.order = self.group.order()
        self.m = m
        self.nr_candidates = list_ctxts[0].vote.length

        dummy_gen_start = time.process_time()
        self.counter_lookup_table = counter_lookup_table

        ### Step 2: We begin by generating the dummy votes
        self.initial_ctxts = list_ctxts
        self.dummies = self.generate_dummies(kp, voting_key, self.initial_ctxts)
        self.overhead = len(self.dummies)
        self.total_votes = self.initial_ctxts + self.dummies
        self.length_total = len(self.total_votes)

        ### Step 3: verifiable shuffle of stripped ciphertexts
        shuffle_start = time.process_time()
        (
            self.ctxts,
            randomizers,
            self.shuffled_ctxts,
            permutation,
            n,
        ) = self.perform_shuffle(self.total_votes)
        self.length_total = len(self.ctxts)
        # Attention, this is dangerous for it to be so. The prover should not know the values used to generate the
        # commitment key. However, for sake of computing evaluation times, we do so.
        self.com_pk = commitment.PublicKey(self.group, n)
        self.proof_of_shuffle = ShuffleArgument(
            self.com_pk,
            self.pk,
            self.ctxts,
            self.shuffled_ctxts,
            permutation,
            randomizers,
        )

        # Now we return to 'normal shape' of shuffled ciphertexts, i.e. one list of size length total
        self.reshaped_shuffled_ctxts = [
            b for sublist in self.shuffled_ctxts for b in sublist
        ]
        self.permutation = [p for sublist in permutation for p in sublist]
        reshaped_randomizers = [r for sublist in randomizers for r in sublist]

        shuffle_end = time.process_time()

        ### Step 4: Decrypting vids and counters and proving correctness
        stripped_ballots_dec_vid_index = self.decrypt_and_proof(kp)
        decrypt_time = time.process_time()

        ### Step 5: Group ballots per vid and index, and reencrypting ballots
        # Now we want to group ballots by vid, take the one with highest counter, and re-encrypt (with its respective
        # proof). To make the reencryption proof, we need the list of tags of the respective vid.
        df = pd.DataFrame(
            stripped_ballots_dec_vid_index, columns=["vid", "index", "tag", "entry_nr"]
        )

        # We select the entries with the maximum index. The entry_number is the position in self.reshaped_shuffled_ctxts
        indexes = df.groupby(["vid"], sort=False)["index"].transform(max) == df["index"]
        # maximum_tag = df[indexes]['tag']
        passed_entry_numbers = df[indexes]["entry_nr"].tolist()

        # We generate lists, per vid, of the respective tags
        self.tags = df.groupby(["vid"], sort=False)["tag"].apply(list)
        self.nr_ballot_groups = len(self.tags)
        # df.grouopby(['vid'], sort=False).apply(lambda x: x.sort_values('index')['tag'].tolist()

        # We reencrypt and generate the respective proof for each ciphertext in the list of passed ciphertexts
        # Currently we do one reencryption proof per candidate, this can be optimized.
        self.reencrypted_votes, self.reencryption_proofs = self.reencrypt_and_proof(
            kp, self.reshaped_shuffled_ctxts, passed_entry_numbers, self.tags
        )
        reencrypt_time = time.process_time()

        ### Step 6: randomize and shuffle selected votes
        # TODO: nr_candidates should be removed from this code, or at least not treated as
        # the length of a VoteVector anymore. Ask Wouter
        assert self.nr_candidates == 1
        self.selected_votes = [v.ballot[0] for v in self.reencrypted_votes]

        # We shuffle the reencrypted_votes ones more so we can drop the ones corresponding to dummy ballots
        (
            self.selected_votes_padded,
            final_randomizers,
            self.selected_votes_shuffled,
            permutation,
            n,
        ) = self.perform_shuffle(self.selected_votes)
        self.final_length_total = len(self.ctxts)
        self.final_com_pk = commitment.PublicKey(self.group, n)
        self.final_proof_of_shuffle = ShuffleArgument(
            self.final_com_pk,
            self.pk,
            self.selected_votes_padded,
            self.selected_votes_shuffled,
            permutation,
            final_randomizers,
        )
        final_shuffle_end = time.process_time()

        # TODO: restructure ciphertexts as well so that verify can actually compute on them if needed
        self.final_permutation = [p for sublist in permutation for p in sublist]
        reshaped_final_randomizers = [
            r for sublist in final_randomizers for r in sublist
        ]

        ### Step 7: open dummy ballots that should be ignored in the next phase
        # TODO: we should open the correct ballots (using permutations etc.)
        # Largely omitting because computational cost is low.

        # WARNING: these indices are for performance purposes only, they are not yet correct
        self.revealed_dummy_indices = range(self.nr_ballot_groups - self.nr_voters)
        self.revealed_dummy_randomizers = []
        for idx in self.revealed_dummy_indices:
            self.revealed_dummy_randomizers.append(
                reshaped_randomizers[idx] * reshaped_final_randomizers[idx]
            )
        final_open_end = time.process_time()

        # Aggregate and tally processing times
        self.time_dummy_gen = shuffle_start - dummy_gen_start
        self.time_shuffle = shuffle_end - shuffle_start
        self.time_decrypt = decrypt_time - shuffle_end
        self.time_reencrypt = reencrypt_time - decrypt_time
        self.time_final_shuffle = final_shuffle_end - reencrypt_time
        self.time_final_open = final_open_end - final_shuffle_end

    def verify(self):
        """Verify that the full tally proceedure has been correctly performed. Again, to avoid passing variables, we define
        everything that should be posted in the BB as a class variable. This should not be done in a proper implementation.

        todo: verify function should get the result of the filtering as input

        # Example:
        # >>> G = EcGroup()
        #     >>> key_pair = elgamal.KeyPair(G)
        #     >>> pk = key_pair.pk
        #     >>> m = 2
        #     >>> nr_candidates = 1
        #     >>> number_ballots = 10
        #     >>> security_param = 128
        #     >>> vids, counters = election_setup(G, number_ballots, security_param)
        #     >>> ctxts, counter_lookup_table, _ = generate_ballots(pk, vids, counters, nr_candidates, single_vote=False, revotes_fraction=0.4)
        #     >>>
        #     >>> tally_proof = Filter(key_pair, key_pair.pk, ctxts, m, counter_lookup_table)
        #     >>> tally_proof.verify()
        #     True

        """

        verification_start = time.process_time()

        # Step 2a + 2b: verify tags of dummy ballots
        # verify all dummies encrypt zero
        dummies_verif = []
        zero_vote = VoteVector(
            [self.election_key.encrypt(self.group.infinite(), 0)] * self.nr_candidates
        )
        dummy_tag = elgamal.Ciphertext(self.group.infinite(), self.group.generator())
        for dummies in self.dummies:
            dummies_verif.append(dummies.vote == zero_vote)
            # TODO: added this check, should be here, make sure this doesn't break things
            dummies_verif.append(dummies.tag == dummy_tag)
        dummies_time_verif = time.process_time()

        # Step 2c: Verify the shuffle proof
        ver_shuffle_proof = self.proof_of_shuffle.verify(
            self.com_pk, self.pk, self.ctxts, self.shuffled_ctxts
        )
        shuffle_time_ver_end = time.process_time()

        # Step 2d: Verify correctness of decryptions of vid and indexes
        proof_decryptions = []
        for index, entry in enumerate(self.decrypted_vid_index):
            proof_decryptions.append(
                entry[1].verify(self.reshaped_shuffled_ctxts[index].vid, entry[0])
            )
            proof_decryptions.append(
                entry[3].verify(self.reshaped_shuffled_ctxts[index].index, entry[2])
            )
        dec_time_ver = time.process_time()

        # Step 2e: Verify reencryption and grouping
        # MISISNG: verify should comput its own grouping, but ok
        # Verify correctness of reencryptions. Here we are verifying the reencryptions of each ciphertext corresponding
        # to a particular candidate.
        # TODO: are we sure this "corresponding to a particular candidate" is still correct?
        proof_reencryptions = []
        for index, proof in enumerate(self.reencryption_proofs):
            proof_reencryptions.append(
                proof[1].verify(
                    self.pk,
                    self.pk,
                    getattr(self.tags, str(self.decrypted_vid_index[proof[0]][0])),
                    self.reshaped_shuffled_ctxts[proof[0]].vote,
                )
            )
        reenc_time_ver = time.process_time()

        # Step 2f: Verify the final shuffle proof
        ver_final_shuffle_proof = self.final_proof_of_shuffle.verify(
            self.final_com_pk,
            self.pk,
            self.selected_votes_padded,
            self.selected_votes_shuffled,
        )
        final_shuffle_time = time.process_time()

        # Step 2g: Verify opening of dummy ballots before tallying
        # TODO: for now just recomputing ciphertexts
        for ind, rand in zip(
            self.revealed_dummy_indices, self.revealed_dummy_randomizers
        ):
            zero_vote = VoteVector(
                [self.election_key.encrypt(self.group.infinite(), rand)]
                * self.nr_candidates
            )
            # TODO: actually compare against something
        final_open_time = time.process_time()

        self.dummies_time_ver = dummies_time_verif - verification_start
        self.shufle_time_ver = shuffle_time_ver_end - dummies_time_verif
        self.dec_time_ver = dec_time_ver - shuffle_time_ver_end
        self.reenc_time_ver = reenc_time_ver - dec_time_ver
        self.final_shuffle_time_ver = final_shuffle_time - reenc_time_ver
        self.final_open_time_ver = final_open_time - final_shuffle_time

        return (
            ver_shuffle_proof
            and all(proof_decryptions)
            and all(proof_reencryptions)
            and all(dummies_verif)
            and ver_final_shuffle_proof
        )

    def reencrypt_and_proof(self, kp, ctxts, entry_numbers, tags):
        """
        We need the sk to determine whether it is a dummy voter or a real voter
        """

        reencrypted_votes = []
        reencryption_proofs = []
        for i in entry_numbers:
            ballot = ctxts[i]
            vid = ballot.vid.decrypt(kp.sk)
            max_tag = ballot.tag
            tags_vid = getattr(tags, str(vid))
            proof = ReencryptionProof(kp, kp.pk, tags_vid, ballot.vote, max_tag=max_tag)

            # We also include the entry number i in order to verify vs the correct position of ciphertext.
            reencryption_proofs.append([i, proof])
            reencrypted_votes.append(proof.reencrypted_vote)

        return reencrypted_votes, reencryption_proofs

    def generate_dummies(self, kp, voting_key, list_ctxts):
        """
        The tallying server will be the one responsible for this process. It
        must decrypt vids and group votes, calculate the cover for nr_vis,
        len(list_ctxts), and add dummies accordingly to the outcome of the
        cover.
        """
        sk = kp.sk

        # We generate a dictionary with vid and number of dummies to add (start = 0)
        vid_counter_ = []

        # We decrypt vid and counters here, so we remember them so
        # we do not have to decrypt them again.
        self.decrypted_vid = []
        self.decrypted_counter = []

        for ballot in list_ctxts:
            vid = ballot.vid.decrypt(sk)
            counter = ballot.index.decrypt(sk)
            self.decrypted_vid.append(vid)
            self.decrypted_counter.append(counter)
            vid_counter_.append([vid, self.counter_lookup_table[counter]])

        df = pd.DataFrame(vid_counter_, columns=["vid", "min_counter"])
        nr_ocurrences = df.groupby(["vid"], sort=False).size().reset_index()
        self.nr_voters = nr_ocurrences.shape[0]
        nr_ballots = len(list_ctxts)

        if self.nr_voters == nr_ballots:
            return []

        # Now we create a dictionary with |vid|min_counter|nr_ocurrences|
        min_counter = df.groupby(["vid"], sort=False)["min_counter"].min().reset_index()
        df_vid_counter_occ = pd.merge(nr_ocurrences, min_counter)
        df_vid_counter_occ.columns = ["vid", "nr_ocurrences", "min_counter"]

        # If we order them we can do a trick for not re-visiting always the beggining of the list
        # Intetion is to loop through all values of the list, and add a dummy everytime needed
        df_vid_counter_occ = df_vid_counter_occ.sort_values(
            by=["nr_ocurrences"]
        ).reset_index(drop=True)

        cover = compute_cover(self.nr_voters, nr_ballots)
        dummy_votes = []

        for key, val in cover.items():
            while val > 0:
                try:
                    row = df_vid_counter_occ.iloc[0]
                except:
                    # FIXME: Horrible horrible hack, ensure that we keep adding dummmies
                    row = {}
                    row["nr_ocurrences"] = key + 1
                    row["vid"] = 0

                vid = row["vid"]

                if row["nr_ocurrences"] > key:
                    # for loop
                    ocurrence = 1
                    dummy_vote, vid, min_counter = self.create_single_dummy(
                        voting_key, dummy=True
                    )
                    dummy_votes.append(dummy_vote)

                    while ocurrence < key:
                        dummy_vote, _, _ = self.create_single_dummy(
                            voting_key, vid, min_counter, dummy=True
                        )
                        dummy_votes.append(dummy_vote)
                        min_counter -= 1
                        ocurrence += 1
                    val -= 1
                else:
                    particular_ocurrences = row["nr_ocurrences"]
                    while particular_ocurrences < key:
                        min_counter = row["min_counter"]
                        # TODO if dummy=false, maybe "create_single_dummy" needs a better name
                        dummy_vote, _, _ = self.create_single_dummy(
                            voting_key, vid, min_counter, dummy=False
                        )
                        dummy_votes.append(dummy_vote)
                        min_counter -= 1
                        particular_ocurrences += 1
                    val -= 1
                    df_vid_counter_occ = df_vid_counter_occ.drop(0).reset_index(
                        drop=True
                    )

        return dummy_votes

    def create_single_dummy(self, pk, vid=None, counter=None, dummy=True):
        voting_key = pk
        infinity = voting_key.group.infinite()
        ts_key = self.pk

        dummy_vote = VoteVector(
            [elgamal.Ciphertext(infinity, infinity) for _ in range(self.nr_candidates)]
        )
        dummy_tag = elgamal.Ciphertext(
            ts_key.group.infinite(), ts_key.group.generator()
        )
        real_tag = elgamal.Ciphertext(ts_key.group.infinite(), ts_key.group.infinite())

        if vid and counter:
            encrypted_vid = ts_key.encrypt(vid)
            counter_elem = (counter - 1) * self.generator

            self.decrypted_vid.append(vid)
            self.decrypted_counter.append(counter_elem)

            encrypted_counter = ts_key.encrypt(counter_elem)
            self.counter_lookup_table[counter_elem] = counter - 1

            # Add deterministic tag
            encrypted_tag = dummy_tag if dummy else real_tag

            return (
                BallotBundle(
                    encrypted_vid, encrypted_counter, encrypted_tag, dummy_vote
                ),
                None,
                None,
            )
        else:
            vid = self.order.random() * self.generator
            counter = self.order.random()
            counter_elem = counter * self.generator
            self.counter_lookup_table[counter_elem] = counter

            self.decrypted_vid.append(vid)
            self.decrypted_counter.append(counter_elem)

            encrypted_vid = ts_key.encrypt(vid)
            encrypted_counter = ts_key.encrypt(counter_elem)
            encrypted_tag = dummy_tag

            return (
                BallotBundle(
                    encrypted_vid, encrypted_counter, encrypted_tag, dummy_vote
                ),
                vid,
                counter,
            )

    def decrypt_and_proof(self, kp):
        """
        The function decrypts and proofs correct decryption. It publishes (makes a class variable) an array with
        [decrypted_vid, proof_dec_vid, decrypted_index, proof_dec_ind].

        It returns the vid, counter and tags, together with an index of the corresponding ballot in
        self.reshaped_shuffled_ctxts.
        """
        # todo: unify decryption proof?
        self.decrypted_vid_index = []

        # stripped_ballots_dec_vid_index will be used later to generate a dataframe to make the vote filtering
        stripped_ballots_dec_vid_index = []

        for i, ballot in enumerate(self.reshaped_shuffled_ctxts):
            vid = self.decrypted_vid[self.permutation[i]]
            proof_vid = CorrectDecryption(ballot.vid, vid, kp)

            index = self.decrypted_counter[self.permutation[i]]
            proof_index = CorrectDecryption(ballot.index, index, kp)

            self.decrypted_vid_index.append([vid, proof_vid, index, proof_index])
            stripped_ballots_dec_vid_index.append(
                [str(vid), self.counter_lookup_table[index], ballot.tag, i]
            )

        return stripped_ballots_dec_vid_index

    def perform_shuffle(self, input_ctxts):
        """
        Re-shape and shuffle to be accepted in proof format
        """
        ctxts, n, = self.prepare_ctxts(input_ctxts, self.m, self.election_key)
        length_total = len(ctxts)
        randomizers = [self.order.random() for _ in range(length_total)]
        permutation = np.random.permutation(length_total).tolist()
        shuffled_ctxts = [
            self.pk.reencrypt(ctxts[permuted_index], ephemeral_key=randomizers[index])
            for index, permuted_index in enumerate(permutation)
        ]

        ctxts = ShuffleArgument.reshape_m_n(ctxts, self.m)
        randomizers = ShuffleArgument.reshape_m_n(randomizers, self.m)
        shuffled_ctxts = ShuffleArgument.reshape_m_n(shuffled_ctxts, self.m)
        permutation = ShuffleArgument.reshape_m_n(permutation, self.m)

        return ctxts, randomizers, shuffled_ctxts, permutation, n

    def prepare_ctxts(self, ctxts, m, election_key):
        """
        Prepares the ctxts list to a compatible ctxts list for the format m * n for the given m, i.e. we append encrypted
        zeros (with randomization 0) till we reach a length of m * (ceil(len(ctxts) / m)
        """
        import math

        if len(ctxts) < m:
            raise ValueError("Lengths of ciphertexts expected greater than value m.")
        n = math.ceil(len(ctxts) / m)
        infinity = election_key.pk.group.infinite()

        dummies = []
        if type(ctxts[0]) == BallotBundle:
            # TODO: attention, we are assuming all values in the BallotBundle come from the same group.
            for _ in range(m * n - len(ctxts)):
                dummy, vid, counter = self.create_single_dummy(election_key, dummy=True)
                dummies.append(dummy)
        elif type(ctxts[0]) == VoteVector:
            # TODO: this should not be necessary anymore
            for _ in range(m * n - len(ctxts)):
                dummy_vote = VoteVector(
                    [
                        elgamal.Ciphertext(infinity, infinity)
                        for _ in range(self.nr_candidates)
                    ]
                )
                dummies.append(dummy_vote)
        elif type(ctxts[0]) == elgamal.Ciphertext:
            for _ in range(m * n - len(ctxts)):
                dummy_vote = elgamal.Ciphertext(infinity, infinity)
                dummies.append(dummy_vote)
        else:
            raise ValueError(
                "Unexpected type of ciphertexts. Expecting BallotBundle or VoteVector, got {0}",
                type(ctxts[0]),
            )

        ctxts.extend(dummies)
        return ctxts, n

    def get_times(self):
        return [self.time_shuffle, self.time_decrypt, self.time_reencrypt]


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


def generate_ballots(
    pk, vids, counters, nr_candidates, single_vote=True, revotes_fraction=0.0
):
    G = pk.group
    infinity = pk.group.infinite()
    lookup_table = {}
    lookup_table[infinity] = 0
    vote = VoteVector([pk.encrypt(1 * G.generator()) for _ in range(nr_candidates)])
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


if __name__ == "__main__":
    import doctest

    doctest.testmod()
    G = EcGroup()
    key_pair = elgamal.KeyPair(G)
    pk = key_pair.pk
    m = 2
    nr_candidates = 1
    number_ballots = 1000
    security_param = 128

    # Setup the vids, counters and the lookup table of the counters.
    vids, counters = election_setup(G, number_ballots, security_param)

    # Generate all the ballots for the respective number of voters (no-revoting now)
    ctxts, counter_lookup_table, _ = generate_ballots(
        pk, vids, counters, nr_candidates, single_vote=False, revotes_fraction=0.1
    )

    full_tally_time = time.process_time()
    tally_proof = Filter(key_pair, key_pair.pk, ctxts, m, counter_lookup_table)
    print(
        "Overhead: {0:.2f} % dummies".format(
            (tally_proof.overhead / number_ballots) * 100
        )
    )
    print(
        "Full filtering time:",
        tally_proof.time_shuffle
        + tally_proof.time_dummy_gen
        + tally_proof.time_decrypt
        + tally_proof.time_reencrypt,
    )

    time_verify = time.process_time()
    print(tally_proof.verify())
    print("Full tally verify", time.process_time() - time_verify)
