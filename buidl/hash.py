try:
    from buidl.chash import *  # noqa: F401,F403
except ModuleNotFoundError:
    from buidl.phash import *  # noqa: F401,F403
