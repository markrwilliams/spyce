try:  # pragma: no cover
    reduce = reduce
except NameError:  # pragma: no cover
    from functools import reduce

try:
    long = long
except NameError:
    long = int
