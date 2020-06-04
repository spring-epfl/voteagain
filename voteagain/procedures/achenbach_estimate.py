import math
import time
from petlib.ec import EcGroup

# One mult, one NIZKP (1 mult), 3 encryptions (involving 2 mults each),
# 3 decryptions (involving 1 mult each) for each row out of NMBR_VOTERS^2
# rows, three shuffles of NMBR_VOTERS^2
# (with 6 mult each) and one shuffle with NMBR_VOTERS (with
# 6NMBR_VOTERS mults). Total of 29 * (NMBR_VOTERS^2) + 6NMBR_VOTERS.

# First we compute the average of the point multiplication
G = EcGroup()
generator = G.generator()
random = G.order().random()
initial_time = time.time()
for _ in range(10000):
    random * generator

average_mult = (time.time() - initial_time) / 10000
print("average multiplication: ", average_mult)

random_point = random * generator
addition_time = time.time()
for _ in range(10000):
    random_point + generator
average_addition = (time.time() - addition_time) / 10000
print("average addition: ", average_addition)

tally = []
total_ballots = [
    100.0,
    215.0,
    464.0,
    1000.0,
    2154.0,
    4641.0,
    10000.0,
    21544.0,
    46416.0,
    100000.0,
    215443.0,
    464159.0,
    1000000.0,
]

for voters in total_ballots:
    square = voters * voters

    tally.append(29 * square * average_mult)

nr_voters = 176574

print(29 * (nr_voters ** 2) * average_mult)

# import matplotlib.pyplot as plt
#
#
# fig, ax = plt.subplots(figsize=(4, 2.5))
# ax.errorbar(total_ballots, tally, label="Achenbach", color="blue", fmt='o-')
#
# ax.set_ylabel('Time (s)')
# ax.set_xscale('log')
# ax.set_yscale('log')
# ax.set_xlabel("#voters")
# ax.legend(loc=0)
# plt.show()
