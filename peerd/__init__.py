from collections import defaultdict
from logging import getLogger

LOGGER = getLogger('__main__')
nested_dict = lambda: defaultdict(nested_dict)
