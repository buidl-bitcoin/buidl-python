def is_libsec_enabled():
    try:
        from buidl import cecc  # noqa: F401

        return True
    except ModuleNotFoundError:
        return False
