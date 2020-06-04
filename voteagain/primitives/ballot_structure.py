"""
Ballots
"""

from petlib.ec import EcGroup


class BallotBundle:
    # TODO: convert into something a little bit more generic?
    """Multiple ElGamal ciphertexts element

    v = [vid, index, tag, vote]

    """

    def __init__(self, encrypted_vid, encrypted_index, encrypted_tag, encrypted_vote):
        self.vid = encrypted_vid
        self.index = encrypted_index
        self.tag = encrypted_tag
        self.vote = encrypted_vote
        if type(self.vote) != VoteVector:
            raise ValueError(
                "Expected type to be VoteVector. Got {0}".format(type(self.vote))
            )

    def __mul__(self, other):
        """Mul"""

        if type(other) == BallotBundle:
            return BallotBundle(
                self.vid * other.vid,
                self.index * other.index,
                self.tag * other.tag,
                self.vote * other.vote,
            )
        else:
            return BallotBundle(
                self.vid * other,
                self.index * other,
                self.tag * other,
                self.vote * other,
            )

    def __pow__(self, exponent):
        return BallotBundle(
            self.vid ** exponent,
            self.index ** exponent,
            self.tag ** exponent,
            self.vote ** exponent,
        )

    def __eq__(self, other):
        return (
            self.vid == other.vid
            and self.index == other.index
            and self.tag == other.tag
            and self.vote == other.vote
        )

    def tolist(self):
        return (
            self.vid.tolist()
            + self.index.tolist()
            + self.tag.tolist()
            + self.vote.tolist()
        )

    # def checkpoints(self):
    #     return all([pk.group.check_point(self.announcement_reencryption[i].vid.c1) and
    #                 pk.group.check_point(self.announcement_reencryption[i].vid.c2) and
    #                 pk.group.check_point(self.announcement_reencryption[i].index.c1) and
    #                 pk.group.check_point(self.announcement_reencryption[i].index.c2) and
    #                 pk.group.check_point(self.announcement_reencryption[i].tag.c1) and
    #                 pk.group.check_point(self.announcement_reencryption[i].tag.c2) and
    #                 pk.group.check_point(self.announcement_reencryption[i].vote.c1) and
    #                 pk.group.check_point(self.announcement_reencryption[i].vote.c2)])


class ValuesVector:
    """Multiple values of group G element

    e.g: v = [randomizer_vid, randomizer_index, randomizer_tag, randomizer_vote]
    """

    def __init__(
        self, randomizer_vid, randomizer_index, randomizer_tag, randomizer_vote
    ):
        self.vid = randomizer_vid
        self.index = randomizer_index
        self.tag = randomizer_tag
        self.vote = randomizer_vote

    def __add__(self, other):
        """Add a values vector with either a Values vector or a single value
            Example:
                >>> a = ValuesVector(1, 2, 3, 4)
                >>> b = ValuesVector(5, 6, 7, 8)
                >>> a + b == ValuesVector(6, 8, 10, 12)
                True
                >>> a + 2 == ValuesVector(3, 4, 5, 6)
                True


            """
        if type(other) == ValuesVector:
            return ValuesVector(
                self.vid + other.vid,
                self.index + other.index,
                self.tag + other.tag,
                self.vote + other.vote,
            )
        else:
            return ValuesVector(
                self.vid + other,
                self.index + other,
                self.tag + other,
                self.vote + other,
            )

    def __neg__(self):
        return ValuesVector(-self.vid, -self.index, -self.tag, -self.vote)

    def __eq__(self, other):
        return (
            self.vid == other.vid
            and self.index == other.index
            and self.tag == other.tag
            and self.vote == other.vote
        )

    def __mul__(self, other):
        if type(other) == ValuesVector:
            return ValuesVector(
                self.vid * other.vid,
                self.index * other.index,
                self.tag * other.tag,
                self.vote * other.vote,
            )
        else:
            return ValuesVector(
                self.vid * other,
                self.index * other,
                self.tag * other,
                self.vote * other,
            )


class VoteVector:
    """Vector forming an encrypted vote, with one entry per candidate"""

    def __init__(self, vote_list):
        self.ballot = vote_list
        self.group = vote_list[0].group
        self.length = len(vote_list)

    def __mul__(self, other):
        if type(other) == VoteVector:
            return VoteVector([x * y for x, y in zip(self.ballot, other.ballot)])
        else:
            return VoteVector([x * other for x in self.ballot])

    def __pow__(self, exponent):
        if type(exponent) == VoteVector:
            raise ValueError("Two VoteVector types cannot be multiplied")
        return VoteVector([x ** exponent for x in self.ballot])

    def __eq__(self, other):
        return all([self.ballot, other.ballot])

    def c1(self, pointvector=False):
        """The reason why we return a list of lists is to construct the shuffle in a more optimal way. See ctxt_weighted_sum
        in efficient_shuffle.multi_exponantiation_argument"""
        if pointvector:
            return PointVector([vote.c1 for vote in self.ballot])
        else:
            return [[vote.c1] for vote in self.ballot]

    def c1_pow(self, exponent):
        return PointVector([c1[0] ** exponent for c1 in self.c1()])

    def c2(self, pointvector=False):
        """The reason why we return a list of lists is to construct the shuffle in a more optimal way. See ctxt_weighted_sum
                in efficient_shuffle.multi_exponantiation_argument"""
        if pointvector:
            return PointVector([vote.c2 for vote in self.ballot])
        else:
            return [[vote.c2] for vote in self.ballot]

    def c2_pow(self, exponent):
        return PointVector([c2[0] ** exponent for c2 in self.c1()])

    def tolist(self):
        return sum([vote.tolist() for vote in self.ballot], [])


class PointVector:
    def __init__(self, point_list):
        self.list = point_list
        self.group = self.list[0].group
        self.length = len(self.list)

    def __mul__(self, other):
        """
        Multiply two list of group values
        Example:
            >>> G = EcGroup()
            >>> generator = G.generator()
            >>> a = PointVector([2 * generator, 4 * generator])
            >>> b = PointVector([4 * generator, 2 * generator])
            >>> c = PointVector([6 * generator, 6 * generator])
            >>> a * b == c
            True
        """
        return PointVector(
            [
                value_list + value_other
                for value_list, value_other in zip(self.list, other.list)
            ]
        )

    def __truediv__(self, other):
        """
        Divide two list of group values
        Example:
            >>> G = EcGroup()
            >>> generator = G.generator()
            >>> a = PointVector([4 * generator, 4 * generator])
            >>> b = PointVector([2 * generator, 2 * generator])
            >>> a / b == b
            True
        """
        return PointVector(
            [
                value_list - value_other
                for value_list, value_other in zip(self.list, other.list)
            ]
        )

    def __pow__(self, power):
        """
        Power each entry of PointVector by exponent
        Example:
            >>> G = EcGroup()
            >>> generator = G.generator()
            >>> a = PointVector([2 * generator, 4 * generator])
            >>> a ** 3 == PointVector([6 * generator, 12 * generator])
            True
        """
        return PointVector([power * value_list for value_list in self.list])

    def __eq__(self, other):
        return all([a == b for a, b in zip(self.list, other.list)])

    def tolist(self):
        return [values for values in self.list]


if __name__ == "__main__":
    import doctest

    doctest.testmod()
