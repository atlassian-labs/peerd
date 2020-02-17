# Built in
import datetime
from datetime import timedelta
from functools import wraps
from typing import Callable, Optional, Union

# Third Party
from cachelib import SimpleCache

# Global data structures
cache = SimpleCache()


def memoize(timeout: Optional[Union[int, datetime.timedelta]] = None, invalidate: bool = False) -> Callable:
    """ Decorator to cache a function by name/args

    Uses the SimpleCache
    Example usage:
    ```
    @memoize(timedelta(minutes=55))
    def get_role_credentials(account: str, sts_client) -> dict:
    ```

    :param timeout: How long to keep the result
    :param invalidate: Clear the cache before executing the decorated
    """
    if isinstance(timeout, timedelta):
        timeout = timeout.seconds

    def decorator(decorated):
        @wraps(decorated)
        def wrapper(*args, **kwargs):
            key = f'{decorated.__name__}{args}{kwargs}'
            if invalidate:
                cache.delete(key)
            ret = cache.get(key)
            if ret is None:
                ret = decorated(*args, **kwargs)
                cache.set(key, ret, timeout=timeout)
            return ret

        return wrapper

    return decorator
