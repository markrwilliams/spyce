try:  # pragma: no cover
    reduce = reduce
except NameError:  # pragma: no cover
    from functools import reduce

try:  # pragma: no cover
    long = long
except NameError:  # pragma: no cover
    long = int
