import math

MAX_K = 64


def cover_size(c):
    total = 0
    for k, v in c.items():
        total += k * v
    return total


def compute_cover(nr_voters, nr_ballots, max_ballots_dict=None):
    """Compute the best cover of groups for the padding scheme

    This function tries to guess which bucket sizes are good. For now,
    it only considers exponential bucket sizes. Then it outputs a
    dictionary of the form {groupsize: nr_voters_in_this_group}

    Parameters
    ----------
    nr_voters : int
        The number of voters
    nr_ballots : int
        The number of ballots that have been recorded by the system
    max_ballots_dict: dictionary, optional
        Dictionary giving key value pairs of the form (nr_voters, max_nr_ballots).
        The dictionary keys should sum up to nr_voters.

    Example:
        >>> compute_cover(2, 9)
        {1: 1, 2: 1, 4: 1, 8: 1, 16: 0}
        >>> compute_cover(2, 7)
        {1: 1, 3: 1, 9: 1}
        >>> compute_cover(2, 2)
        {1: 2}

    """

    # If max_votes is unset, use "all ballots" as the limit
    if max_ballots_dict is None:
        max_ballots_dict = {}
        max_ballots_dict[nr_voters] = nr_ballots

    if max(max_ballots_dict.values()) is None:
        raise RuntimeError("nr ballots max is none")

    # Make sure that max_ballots_dict is correctly formed
    if sum(max_ballots_dict.keys()) != nr_voters:
        raise RuntimeError("Supplied max_ballots_dict does not add up to nr_voters")

    best_cover = None
    best_count = nr_voters * nr_ballots

    for k in range(24, (MAX_K + 1) * 12):
        dummy_count, cover = compute_cover_k(
            nr_voters, nr_ballots, max_ballots_dict, k / 12.0
        )
        if dummy_count < best_count:
            best_count = dummy_count
            best_cover = cover

    return best_cover


def compute_cover_k(nr_voters, nr_ballots, max_ballots_dict, k):
    """ Compute a cover given the base of the group sizes

    Example:
        >>> compute_cover_k(2, 9, {2: 9}, 2)
        (6, {1: 1, 2: 1, 4: 1, 8: 1, 16: 0})
        >>> compute_cover_k(2, 9, {2: 9}, 8)
        (8, {1: 1, 8: 2, 64: 0})
        >>> compute_cover_k(2, 2, {2: 2},2)
        (0, {1: 2})
        >>> compute_cover_k(2, 7, {2: 7},2)
        (12, {1: 1, 2: 1, 4: 2, 8: 1})
        >>> compute_cover_k(2, 7, {2: 7}, 3)
        (6, {1: 1, 3: 1, 9: 1})

        """
    total = 0

    if max_ballots_dict is None:
        raise RuntimeError("Should not happen, dict empty")

    # Nobody casts more than max_ballots, so we don't need to consider and fill
    # larger buckets.
    max_ballots = max(max_ballots_dict.values())
    max_bucket = int(math.ceil(math.log(max_ballots, k) + 1))

    if nr_voters == nr_ballots:
        return 0, {1: nr_voters}

    cover = {}

    min_size = 1
    for bucket_size in [int(k ** b) for b in range(0, max_bucket)]:
        # We cannot assign all voters if nr_ballots > nr_voters
        # because then we would have left-over ballots
        if bucket_size == 1:
            if nr_ballots > nr_voters:
                assignable_voters = nr_voters - 1

        # Assign at most assignable_voters to this bucket so that
        # the remaining ballots can make up the known number of voters.
        if bucket_size > 1:
            assignable_voters = (nr_ballots - nr_voters) // (min_size - 1)

        # Determine maximum number of voters able to cast min_size votes
        nr_eligible_voters = 0
        for v, b in max_ballots_dict.items():
            if b >= min_size:
                nr_eligible_voters += v

        # Make sure that all nr_ballots can be explained with remaining voters
        # outside of the ballot group. We can only assign all voters to a ballot
        # group, if bucket_size * nr_eligible_voters >= nr_ballots.
        if (
            min(nr_ballots // min_size, nr_eligible_voters) == nr_eligible_voters
            and bucket_size * nr_eligible_voters < nr_ballots
        ):
            assignable_voters = nr_eligible_voters - 1

        # Three conditions:
        #  * Assign no more dummy voters than fit given nr_ballots
        #  * Assign no more dummy voters than nr_eligible_voters
        #  * Assign at most assignable voters
        dummy_voters = min(
            nr_ballots // min_size, nr_eligible_voters, assignable_voters
        )

        cover[bucket_size] = dummy_voters

        total += dummy_voters * bucket_size
        min_size = bucket_size + 1

    return total - nr_ballots, cover


if __name__ == "__main__":
    import doctest

    doctest.testmod()
