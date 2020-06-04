#!/bin/sh

TARGET_DIR=data/padding/

VOTERS_MIN_LOG=3.0
VOTERS_MAX_LOG=8.0

VOTE_FACTORS="1.0,1.1,1.25,1.50,2.0,3.0"
VOTES_PER_MIN="1.0,6.0,60.0,694444444444444.4"
CRAZY_FACTORS="0.01,0.05,0.1,1.0"
VOTE_FACTOR_FIX=1.5
VOTES_PER_MIN_FIX=6.0

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
