"""
Correct reencryption
"""

from petlib.ec import EcGroup, Bn

import voteagain.primitives.elgamal as elgamal
from voteagain.primitives.hash_function import compute_challenge
from voteagain.primitives.ballot_structure import VoteVector, PointVector


class ReencryptionProof:
    """Proof of correct re-encryption of the tokens and votes after filtering

    We follow the notation of the paper by Wouter Lueks, Iñigo Querejeta-Azurmendi and Carmela
    Troncoso, "VoteAgain"""

    def __init__(self, kp_tally, pk_vote, tokens, vote, max_tag=None):
        # Security parameters
        self.sec_param = 256
        self.bn_two = Bn.from_num(2)
        self.hash_reduction = self.bn_two.pow(self.sec_param)

        self.pk_tally = kp_tally.pk
        self.group_tally = self.pk_tally.group
        self.order_tally = self.group_tally.order()
        self.pk_vote = pk_vote
        self.tokens = tokens
        if max_tag:
            self.max_tag = max_tag
        else:
            self.max_tag = self.tokens[-1]
        self.dummy = self.max_tag.decrypt(kp_tally.sk) == 1 * kp_tally.group.generator()
        self.vote = vote
        self.number_candidates = self.vote.length
        self.number_dummies = len(tokens)

        last_token_decryption = self.tokens[-1].decrypt(kp_tally.sk)

        self.added_token = tokens[0]
        for token in tokens[1:]:
            self.added_token = self.added_token * token

        if type(self.vote) != VoteVector:
            raise ValueError("Expected vote type of VoteVector")
        # reencryption of vote
        randomizer_reencryption = self.order_tally.random()

        if self.dummy:
            self.reencrypted_vote = VoteVector(
                [
                    pk_vote.encrypt(
                        0 * kp_tally.group.generator(), randomizer_reencryption
                    )
                ]
                * self.number_candidates
            )
        else:
            self.reencrypted_vote = pk_vote.reencrypt(vote, randomizer_reencryption)

        # Prover for dummy
        prover_dummy = DummyVoterReencryptionProver(
            kp_tally,
            pk_vote,
            self.added_token,
            self.reencrypted_vote,
            randomizer_reencryption,
            self.number_dummies,
        )

        # Prover for real
        prover_real = RealVoterReencryptionProver(
            kp_tally,
            pk_vote,
            self.max_tag,
            vote,
            self.reencrypted_vote,
            randomizer_reencryption,
        )

        # If the voter is real
        if last_token_decryption == 0 * self.group_tally.generator():
            self.proof_dummy = prover_dummy.simulate()

            commitment_pk, commitment_token, commitment_vote1, commitment_vote2 = list(
                prover_real.commit()
            )

            # Challenge big proof
            self.main_challenge = compute_challenge(
                [commitment_pk]
                + [commitment_token]
                + commitment_vote1.tolist()
                + commitment_vote2.tolist()
                + [self.proof_dummy.commitment_pk]
                + [self.proof_dummy.commitment_token]
                + self.proof_dummy.commitment_vote1.tolist()
                + self.proof_dummy.commitment_vote2.tolist()
                + self.vote.tolist()
                + self.added_token.tolist()
                + [self.pk_vote.pk]
                + [self.pk_tally.pk],
                self.hash_reduction,
            )

            self.true_challenge = self.main_challenge - self.proof_dummy.challenge
            self.proof_real = prover_real.create_proof(
                [commitment_pk, commitment_token, commitment_vote1, commitment_vote2],
                self.true_challenge,
            )

        # If the voter is dummy
        else:
            self.proof_real = prover_real.simulate()

            commitment_pk, commitment_token, commitment_vote1, commitment_vote2 = list(
                prover_dummy.commit()
            )

            # Challenge big proof
            self.main_challenge = compute_challenge(
                [self.proof_real.commitment_pk]
                + [self.proof_real.commitment_token]
                + self.proof_real.commitment_vote1.tolist()
                + self.proof_real.commitment_vote2.tolist()
                + [commitment_pk]
                + [commitment_token]
                + commitment_vote1.tolist()
                + commitment_vote2.tolist()
                + self.vote.tolist()
                + self.added_token.tolist()
                + [self.pk_vote.pk]
                + [self.pk_tally.pk],
                self.hash_reduction,
            )

            self.true_challenge = self.main_challenge - self.proof_real.challenge
            self.proof_dummy = prover_dummy.create_proof(
                [commitment_pk, commitment_token, commitment_vote1, commitment_vote2],
                self.true_challenge,
            )

    def verify(self, pk_tally, pk_vote, tokens, vote):
        """
        todo: reencryption votes should be an input of the verify function
        Example:
            >>> G = EcGroup()
            >>> kp_tally = elgamal.KeyPair(G)
            >>> pk_tally = kp_tally.pk
            >>> kp_vote = elgamal.KeyPair(G)
            >>> pk_vote = kp_vote.pk
            >>> token = [pk_tally.encrypt(1 * G.generator()), pk_tally.encrypt(0 * G.generator())]
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> proof = ReencryptionProof(kp_tally, pk_vote, token, vote)
            >>> proof.verify(pk_tally, pk_vote, token, vote)
            True

            Now we try for a token of 1 * generator, and vote of zero
            >>> token = [pk_tally.encrypt(1 * G.generator()), pk_tally.encrypt(1 * G.generator()), pk_tally.encrypt(1 * G.generator())]
            >>> vote = VoteVector([pk_vote.encrypt(0 * G.generator())] * 2)
            >>> proof = ReencryptionProof(kp_tally, pk_vote, token, vote)
            >>> proof.verify(pk_tally, pk_vote, token, vote)
            True
        """
        # Challenge big proof
        self.main_challenge = compute_challenge(
            [self.proof_real.commitment_pk]
            + [self.proof_real.commitment_token]
            + self.proof_real.commitment_vote1.tolist()
            + self.proof_real.commitment_vote2.tolist()
            + [self.proof_dummy.commitment_pk, self.proof_dummy.commitment_token]
            + self.proof_dummy.commitment_vote1.tolist()
            + self.proof_dummy.commitment_vote2.tolist()
            + self.vote.tolist()
            + self.added_token.tolist()
            + [self.pk_vote.pk]
            + [self.pk_tally.pk],
            self.hash_reduction,
        )

        verify_challenges = (
            self.main_challenge
            == self.proof_dummy.challenge + self.proof_real.challenge
        )

        verify_real = self.proof_real.verify(
            pk_tally, pk_vote, self.max_tag, vote, self.reencrypted_vote
        )
        verify_dummy = self.proof_dummy.verify(
            pk_tally, pk_vote, self.added_token, self.reencrypted_vote, len(tokens)
        )

        return verify_challenges and verify_real and verify_dummy


class RealVoterReencryptionProver:
    """Proof of correct reencryption for a real voter"""

    def __init__(self, kp_tally, pk_vote, token, vote, reencrypted_vote, randomizer):
        # Security parameters
        self.sec_param = 256
        self.bn_two = Bn.from_num(2)
        self.hash_reduction = self.bn_two.pow(self.sec_param)

        # Public key used for tokens
        self.pk_tally = kp_tally.pk
        self.sk_tally = kp_tally.sk
        self.group_tally = self.pk_tally.group
        self.generator_tally = self.group_tally.generator()
        self.order_tally = self.group_tally.order()

        # Public key used for votes
        self.pk_vote = pk_vote
        self.group_vote = self.pk_vote.group
        self.generator_vote = self.group_vote.generator()
        self.order_vote = self.group_vote.order()

        self.token = token
        self.vote = vote
        self.nr_candidates = self.vote.length
        self.reencrypted_vote = reencrypted_vote
        self.randomizer = randomizer

        self.hiding_sk = None
        self.hiding_randomizer = None

    def commit(self):
        # Announcement
        self.hiding_sk = self.order_tally.random()
        commitment_pk = self.hiding_sk * self.generator_tally

        commitment_token = self.hiding_sk * self.token.c1

        self.hiding_randomizer = self.order_vote.random()
        commitment_vote1 = PointVector(
            [self.hiding_randomizer * self.generator_vote] * self.nr_candidates
        )
        commitment_vote2 = PointVector(
            [self.hiding_randomizer * self.pk_vote.pk] * self.nr_candidates
        )

        return commitment_pk, commitment_token, commitment_vote1, commitment_vote2

    def create_proof(self, commitments, challenge=None):
        # Challenge
        (
            commitment_pk,
            commitment_token,
            commitment_vote1,
            commitment_vote2,
        ) = commitments
        if challenge:
            proof_challenge = challenge
        else:
            proof_challenge = compute_challenge(
                [commitment_pk]
                + [commitment_token]
                + commitment_vote1.tolist()
                + commitment_vote2.tolist()
                + self.vote.tolist()
                + self.token.tolist(),
                self.hash_reduction,
            )

        # Response
        response_sk = self.hiding_sk + self.sk_tally * proof_challenge
        response_randomizer = self.hiding_randomizer + self.randomizer * proof_challenge

        return RealVoterReencryptionProof(
            commitments, [response_sk, response_randomizer], challenge=proof_challenge
        )

    def simulate(self):
        fake_challenge = self.hash_reduction.random()
        fake_response_sk = self.order_tally.random()
        fake_response_randomizer = self.order_vote.random()

        fake_responses = [fake_response_sk, fake_response_randomizer]

        commitment_pk = (
            fake_response_sk * self.pk_tally.generator
            - fake_challenge * self.pk_tally.pk
        )
        commitment_token = fake_response_sk * self.token.c1 - fake_challenge * (
            self.token.c2 - 0 * self.pk_tally.generator
        )

        commitment_vote1 = (
            PointVector(
                [fake_response_randomizer * self.pk_vote.generator] * self.nr_candidates
            )
            / (
                self.reencrypted_vote.c1(pointvector=True)
                / self.vote.c1(pointvector=True)
            )
            ** fake_challenge
        )
        commitment_vote2 = (
            PointVector(
                [fake_response_randomizer * self.pk_vote.pk] * self.nr_candidates
            )
            / (
                self.reencrypted_vote.c2(pointvector=True)
                / self.vote.c2(pointvector=True)
                / PointVector([0 * self.pk_vote.generator] * self.nr_candidates)
            )
            ** fake_challenge
        )

        commitments = [
            commitment_pk,
            commitment_token,
            commitment_vote1,
            commitment_vote2,
        ]

        return RealVoterReencryptionProof(
            commitments, fake_responses, challenge=fake_challenge
        )


class RealVoterReencryptionProof:
    """RealVoterReencryptionProof. Attention, this proof is made so that it can be simulated. Not to
    be used individually."""

    def __init__(self, commitments, responses, challenge=None):
        # Security parameters
        self.sec_param = 256
        self.bn_two = Bn.from_num(2)
        self.hash_reduction = self.bn_two.pow(self.sec_param)

        (
            self.commitment_pk,
            self.commitment_token,
            self.commitment_vote1,
            self.commitment_vote2,
        ) = commitments
        self.response_sk, self.response_randomizer = responses
        self.challenge = challenge

    def verify(self, pk_tally, pk_vote, token, vote, reencrypted_vote):
        """Verify a proof of reencryption

        Example:
            >>> G = EcGroup()
            >>> kp_tally = elgamal.KeyPair(G)
            >>> pk_tally = kp_tally.pk
            >>> kp_vote = elgamal.KeyPair(G)
            >>> pk_vote = kp_vote.pk
            >>> token = pk_tally.encrypt(0 * G.generator())
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> randomizer = G.order().random()
            >>> reencrypted_vote = pk_vote.reencrypt(vote,randomizer)
            >>> prover = RealVoterReencryptionProver(kp_tally, pk_vote, token, vote, reencrypted_vote, randomizer)
            >>> commitments = prover.commit()
            >>> proof = prover.create_proof(commitments)
            >>> proof.verify(pk_tally, pk_vote, token, vote, reencrypted_vote)
            True

            # Cases where should not hold
            >>> proof.verify(pk_tally, pk_vote, token, vote, pk_tally.reencrypt(vote))
            False

            >>> proof.verify(pk_tally, pk_vote, pk_tally.encrypt(4 * G.generator()), vote, reencrypted_vote)
            False

            # Here the token is not an encryption of 0
            >>> token = pk_tally.encrypt(7 * G.generator())
            >>> prover = RealVoterReencryptionProver(kp_tally, pk_vote, token, vote, reencrypted_vote, randomizer)
            >>> commitments = prover.commit()
            >>> proof = prover.create_proof(commitments)
            >>> proof.verify(pk_tally, pk_vote, token, vote, reencrypted_vote)
            False

            # Here the 'reencryption' is an encryption of a different value
            >>> token = pk_tally.encrypt(0 * G.generator())
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> reencrypted_vote = VoteVector([pk_tally.encrypt(7 * G.generator())] * 2)
            >>> prover = RealVoterReencryptionProver(kp_tally, pk_vote, token, vote, reencrypted_vote, randomizer)
            >>> commitments = prover.commit()
            >>> proof = prover.create_proof(commitments)
            >>> proof.verify(pk_tally, pk_vote, token, vote, reencrypted_vote)
            False

            # Checking that the simulation works
            >>> proof = prover.simulate()
            >>> proof.verify(pk_tally, pk_vote, token, vote, reencrypted_vote)
            True

            # Token is not an encryption of 0
            >>> token = pk_tally.encrypt(7 * G.generator())
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> reencrypted_vote = pk_vote.reencrypt(vote,randomizer)
            >>> prover = RealVoterReencryptionProver(kp_tally, pk_vote, token, vote, reencrypted_vote, randomizer)
            >>> proof = prover.simulate()
            >>> proof.verify(pk_tally, pk_vote, token, vote, reencrypted_vote)
            True

            # Here the 'reencryption' is an encryption of a different value
            >>> token = pk_tally.encrypt(0 * G.generator())
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> reencrypted_vote = VoteVector([pk_vote.encrypt(7 * G.generator())] * 2)
            >>> prover = RealVoterReencryptionProver(kp_tally, pk_vote, token, vote, reencrypted_vote, randomizer)
            >>> proof = prover.simulate()
            >>> proof.verify(pk_tally, pk_vote, token, vote, reencrypted_vote)
            True

            """

        nr_candidates = vote.length

        if self.challenge is None:
            self.challenge = compute_challenge(
                [self.commitment_pk]
                + [self.commitment_token]
                + [self.commitment_vote1, self.commitment_vote2]
                + vote.tolist()
                + token.tolist(),
                self.hash_reduction,
            )

        check_pk = (
            self.response_sk * pk_tally.generator
            == self.commitment_pk + self.challenge * pk_tally.pk
        )
        check_token = (
            self.response_sk * token.c1
            == self.commitment_token
            + self.challenge * (token.c2 - 0 * pk_tally.generator)
        )

        check_reencryption1 = (
            PointVector([self.response_randomizer * pk_vote.generator] * nr_candidates)
            == self.commitment_vote1
            * (reencrypted_vote.c1(pointvector=True) / vote.c1(pointvector=True))
            ** self.challenge
        )
        check_reencryption2 = (
            PointVector([self.response_randomizer * pk_vote.pk] * nr_candidates)
            == self.commitment_vote2
            * (
                reencrypted_vote.c2(pointvector=True)
                / vote.c2(pointvector=True)
                / PointVector([0 * pk_vote.generator] * nr_candidates)
            )
            ** self.challenge
        )

        return check_pk and check_token and check_reencryption1 and check_reencryption2


class DummyVoterReencryptionProver:
    """Proof of correct reencryption for a dummy voter"""

    def __init__(
        self,
        kp_tally,
        pk_vote,
        added_token,
        reencrypted_vote,
        randomizer,
        number_dummies,
    ):
        # Security parameters
        self.sec_param = 256
        self.bn_two = Bn.from_num(2)
        self.hash_reduction = self.bn_two.pow(self.sec_param)

        self.pk_tally = kp_tally.pk
        self.sk_tally = kp_tally.sk
        self.group_tally = self.pk_tally.group
        self.generator_tally = self.group_tally.generator()
        self.order_tally = self.group_tally.order()

        self.pk_vote = pk_vote
        self.group_vote = self.pk_vote.group
        self.generator_vote = self.pk_vote.generator
        self.order_vote = self.group_vote.order()

        self.token = added_token
        self.reencrypted_vote = reencrypted_vote
        self.nr_candidates = self.reencrypted_vote.length
        self.randomizer = randomizer
        self.number_dummies = number_dummies

        self.hiding_sk = None
        self.hiding_randomizer = None

    def commit(self):
        # Announcement
        self.hiding_sk = self.order_tally.random()
        commitment_pk = self.hiding_sk * self.generator_tally
        commitment_token = self.hiding_sk * self.token.c1

        self.hiding_randomizer = self.order_vote.random()
        commitment_vote1 = PointVector(
            [self.hiding_randomizer * self.generator_vote] * self.nr_candidates
        )
        commitment_vote2 = PointVector(
            [self.hiding_randomizer * self.pk_vote.pk] * self.nr_candidates
        )

        return commitment_pk, commitment_token, commitment_vote1, commitment_vote2

    def create_proof(self, commitments, challenge=None):
        # Challenge
        (
            commitment_pk,
            commitment_token,
            commitment_vote1,
            commitment_vote2,
        ) = commitments
        if challenge:
            proof_challenge = challenge
        else:
            proof_challenge = compute_challenge(
                [commitment_pk]
                + [commitment_token]
                + commitment_vote1.tolist()
                + commitment_vote2.tolist()
                + self.reencrypted_vote.tolist()
                + self.token.tolist(),
                self.hash_reduction,
            )

        # Response

        response_sk = self.hiding_sk + self.sk_tally * proof_challenge
        response_randomizer = self.hiding_randomizer + self.randomizer * proof_challenge

        return DummyVoterReencryptionProof(
            commitments, [response_sk, response_randomizer], challenge=proof_challenge
        )

    def simulate(self):
        fake_challenge = self.hash_reduction.random()
        fake_response_sk = self.order_tally.random()
        fake_response_randomizer = self.order_vote.random()

        fake_responses = [fake_response_sk, fake_response_randomizer]

        commitment_pk = (
            fake_response_sk * self.pk_tally.generator
            - fake_challenge * self.pk_tally.pk
        )
        commitment_token = fake_response_sk * self.token.c1 - fake_challenge * (
            self.token.c2 - self.number_dummies * self.pk_tally.generator
        )

        commitment_vote1 = (
            PointVector(
                [fake_response_randomizer * self.pk_vote.generator] * self.nr_candidates
            )
            / self.reencrypted_vote.c1(pointvector=True) ** fake_challenge
        )
        commitment_vote2 = (
            PointVector(
                [fake_response_randomizer * self.pk_vote.pk] * self.nr_candidates
            )
            / (
                self.reencrypted_vote.c2(pointvector=True)
                / PointVector([0 * self.pk_vote.generator] * self.nr_candidates)
            )
            ** fake_challenge
        )

        commitments = [
            commitment_pk,
            commitment_token,
            commitment_vote1,
            commitment_vote2,
        ]

        return DummyVoterReencryptionProof(
            commitments, fake_responses, challenge=fake_challenge
        )


class DummyVoterReencryptionProof:
    """DummyVoterReencryptionProof. Attention, this proof is made so that it can be simulated. Not to
    be used individually."""

    def __init__(self, commitments, responses, challenge=None):
        # Security parameters
        self.sec_param = 256
        self.bn_two = Bn.from_num(2)
        self.hash_reduction = self.bn_two.pow(self.sec_param)

        (
            self.commitment_pk,
            self.commitment_token,
            self.commitment_vote1,
            self.commitment_vote2,
        ) = commitments
        self.response_sk, self.response_randomizer = responses
        self.challenge = challenge

    def verify(self, pk_tally, pk_vote, token, reencrypted_vote, number_dummies):
        """Verify a proof of reencryption for dummy voter

        Example:
            >>> G = EcGroup()
            >>> kp_tally = elgamal.KeyPair(G)
            >>> pk_tally = kp_tally.pk
            >>> kp_vote = elgamal.KeyPair(G)
            >>> pk_vote = kp_vote.pk
            >>> number_dummies = G.order().random()
            >>> added_tokens = pk_tally.encrypt(number_dummies * G.generator())
            >>> randomizer = G.order().random()
            >>> reencrypted_vote = VoteVector([pk_vote.encrypt(0 * G.generator(), randomizer)] * 2)
            >>> prover = DummyVoterReencryptionProver(kp_tally, pk_vote, added_tokens, reencrypted_vote, randomizer, number_dummies)
            >>> commitments = prover.commit()
            >>> proof = prover.create_proof(commitments)
            >>> proof.verify(pk_tally, pk_vote, added_tokens, reencrypted_vote, number_dummies)
            True

            # Cases where should not hold
            >>> proof.verify(pk_tally, pk_vote, added_tokens, VoteVector([pk_tally.encrypt(7 * G.generator(), randomizer)] * 2), number_dummies)
            False

            >>> proof.verify(pk_tally, pk_vote, pk_tally.encrypt(4 * G.generator()), reencrypted_vote, number_dummies)
            False

            # Here the token is an encryption of 0
            >>> added_tokens = pk_tally.encrypt(7 * G.generator())
            >>> prover = DummyVoterReencryptionProver(kp_tally, pk_vote, added_tokens, reencrypted_vote, randomizer, number_dummies)
            >>> commitments = prover.commit()
            >>> proof = prover.create_proof(commitments)
            >>> proof.verify(pk_tally, pk_vote, added_tokens, reencrypted_vote, number_dummies)
            False

            # Checking that the simulation works
            >>> proof = prover.simulate()
            >>> proof.verify(pk_tally, pk_vote, added_tokens, reencrypted_vote, number_dummies)
            True

            # Token is an encryption of 0
            >>> added_tokens = pk_tally.encrypt(0 * G.generator())
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> reencrypted_vote = pk_vote.reencrypt(vote,randomizer)
            >>> prover = DummyVoterReencryptionProver(kp_tally, pk_vote, added_tokens, reencrypted_vote, randomizer, number_dummies)
            >>> proof = prover.simulate()
            >>> proof.verify(pk_tally, pk_vote, added_tokens, reencrypted_vote, number_dummies)
            True

            # Here the 'reencryption' is an encryption of a different value
            >>> added_tokens = pk_tally.encrypt(number_dummies * G.generator())
            >>> vote = VoteVector([pk_vote.encrypt(1 * G.generator())] * 2)
            >>> reencrypted_vote = VoteVector([pk_vote.encrypt(7 * G.generator())] * 2)
            >>> prover = DummyVoterReencryptionProver(kp_tally, pk_vote, added_tokens, reencrypted_vote, randomizer, number_dummies)
            >>> proof = prover.simulate()
            >>> proof.verify(pk_tally, pk_vote, added_tokens, reencrypted_vote, number_dummies)
            True

            """
        nr_candidates = reencrypted_vote.length

        if self.challenge is None:
            self.challenge = compute_challenge(
                [self.commitment_pk]
                + [self.commitment_token]
                + [self.commitment_vote1, self.commitment_vote2]
                + reencrypted_vote.tolist()
                + token.tolist(),
                self.hash_reduction,
            )

        check_pk = (
            self.response_sk * pk_tally.generator
            == self.commitment_pk + self.challenge * pk_tally.pk
        )
        check_token = (
            self.response_sk * token.c1
            == self.commitment_token
            + self.challenge * (token.c2 - number_dummies * pk_tally.generator)
        )

        check_reencryption1 = (
            PointVector([self.response_randomizer * pk_vote.generator] * nr_candidates)
            == self.commitment_vote1
            * reencrypted_vote.c1(pointvector=True) ** self.challenge
        )
        check_reencryption2 = (
            PointVector([self.response_randomizer * pk_vote.pk] * nr_candidates)
            == self.commitment_vote2
            * (
                reencrypted_vote.c2(pointvector=True)
                / PointVector([0 * pk_vote.generator] * nr_candidates)
            )
            ** self.challenge
        )

        return check_pk and check_token and check_reencryption1 and check_reencryption2


if __name__ == "__main__":
    import doctest

    doctest.testmod()
