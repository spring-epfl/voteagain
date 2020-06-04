# VoteAgain evaluation
This repository accompanies the paper *VoteAgain: A scalable coercion-resistant
voting system*, by Wouter Lueks, Iñigo Querejeta-Azurmendi and Carmela Troncoso,
which will be included in the 2020 USENIX Security Symposium. This repository
contains the core cryptographic protocols leveraged by VoteAgain, as well as the
overhead calculation of the dummy procedure presented.

The goal of this repository is to enable reproducing the measurements in the paper. 

**Disclaimer:** This code is not production ready. 

## Installing the requirements
*This is likely to fail on a windows only machine due to missing openssl/compiler dependencies.*

Activate virtual environment and install the dependencies:

```python
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Running experiments
Running the bash scripts `run_experiments_*.sh` will run the same experiments
presented in the paper, and save the output in `data/`:

```bash
./run_experiments_distr.sh
./run_experiments_filter.sh
./run_experiments_mix.sh
./run_experiments_padding.sh
```

To have a more granular control of the function calls, you can use the
`voteagain` module. We explain how to use these modules next.

### Running core experiments

All specific experiments support the `-o <PATH>` (or `--out`) option to specify
where output should be written. By default the output is written to
`./data/<folder>`, where `<folder>` is the (short) name of the experiment. If
the target directory does not exists, it is created.

Experiments that gather timings additionally can be passed the `-r <NR>` (or
`--repeptitions`) argument to specify how often the experiment should be
repeated.

#### Proof of correct vote generation

To cast a vote, voters create a ballot that contains an encryption of the
candidate for which they want to cast a vote. The bulletin board must be able to
verify that this encryption is correct, i.e., that it encrypts to a valid
candidate. The time complexity of the proof grows with the number of candidates.

Call

```bash
python -m voteagain encryption --num-candidates 100
```
to measure the proving and verification times for 100 candidates.

#### Full filter procedure

The main procedure in VoteAgain is the Filter procedure executed by the tally
server. This procedure inserts dummy ballots to ensure coercion resistance and
then shuffles and filters ballots so that only the latest ballot of each voter
is selected.

Call

```bash
python -m voteagain filter --num-voters 10000
```

to measure the time to run Filter and VerifyFilter for 10000 voters that cast 1
ballot each. Run `run_experiments_filter.sh` to gather all the data on the
performance of Filter and VerifyFilter used in the paper.

To measure the effect of revoting, you can use the `-p` (or
`--revote-percentage`) option to specify how many extra ballots there are,
expressed as a percentage of the real number of voters. For example, when
specifying running

```bash
python -m voteagain filter --num-voters 10000 --revote-percentage 150
```

the experiment will generate `10000 + 150/100 * 10000 = 25000` ballots by 10000
voters. The tally server adds the required number of dummy ballots to hide
revoting patterns. Given a fixed number of ballots after adding dummies, the
worst case is where each voter cast only one ballot, i.e., `-p 0`, which is the
default. To confirm this, you can run `run_experiments_distr.sh`. It uses a
different number of voters, but ensures that after adding dummies the total
number of ballots is (approximately) 50.000.

#### Verifiable mixing and decrypting

After the tally server has selected the ballots, the trustees run a final mix
and decrypt network to shuffle these ballots, and recover the encrypted
candidates. The time complexity grows linearly in the number of candidates.

Call

```bash
python -m voteagain mix-and-decrypt --num-ciphertexts 100
```
to measure the proving and verification cost for a single trustee given 100 ballots. To rerun the experiment with all the values used in the paper, run `run_experiments_mix.sh`.

#### Bayer-Groth verifiable shuffle

VoteAagain uses Bayer-Groth's verifiable shuffle as a primitive. To gather basic
performance data, run:

```bash
python -m voteagain min-shuffle --num-ciphertexts 1000
```

to measure a shuffle of 1000 ciphertexts.

#### Generating data for padding overhead

The number of dummy ballots added depends on the number of voters, and the total
number of ballots they produced. Some example calls of this script are as follows:

```sh
python -m voteagain padding -o $TARGET_DIR \
    --vote-factors $VOTE_FACTORS \
    --voters-min-log $VOTERS_MIN_LOG \
    --voters-max-log $VOTERS_MAX_LOG

python -m voteagain padding-max-votes -o $TARGET_DIR \
    --votes-per-min $VOTES_PER_MIN \
    --vote-factor-fixed $VOTE_FACTOR_FIX \
    --voters-min-log $VOTERS_MIN_LOG \
    --voters-max-log $VOTERS_MAX_LOG

python -m voteagain padding-max-vote-per-voters -o $TARGET_DIR \
    --crazy-factors $CRAZY_FACTORS \
    --vote-factor-fixed $VOTE_FACTOR_FIX \
    --votes-per-min-fixed $VOTES_PER_MIN_FIX \
    --voters-min-log $VOTERS_MIN_LOG \
    --voters-max-log $VOTERS_MAX_LOG
```

The parameters `--voters-min-log` and `--voters-max-log` specify the base-10
logarithm of the number of voters that the script should iterate over. The
subcommand then determines the overhead of adding dummies in three different
ways:

 1. With no restrictions on how voters vote, expect to honor the average number
    of ballots per voter set by `--vote-factors`.
 2. By restricting how many ballots a voter can cast per minute, determined by
    `--votes-per-min`. This experiments uses `--vote-factor-fixed` to determine
    how many ballots voters cast on average.
 3. As in (2), but additionally restricting how many voters cast more than one
    ballot, determined by `--crazy-factors`. This experiment additionally uses
    `--votes-per-min-fixed` to determine how many ballots voters can cast per
    minute.
 
To regenerate the source files used for the images in the paper, run
`run_experiments_padding.sh`.

## Running tests
This repository also contains some simple tests programs. These tests serve to
verify the basic functionality of the functions. To run them, execute

`python -m pytest`

## Processing data

The Jupyter notebook in `analysis` takes the data produced by the scripts
`run_experiments_distr.sh`, `run_experiments_filter.sh` and
`run_experiments_mix` and produces the remaining sets of graphs in the paper, as
well as reproduces most performance numbers mentioned in the paper.
