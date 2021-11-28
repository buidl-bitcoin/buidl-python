import socket

from os import getenv

# Disable networking during pytest
# https://www.tonylykke.com/posts/2018/07/31/disabling-the-internet-for-pytest/


def guard(*args, **kwargs):
    raise Exception("I told you not to use the Internet!")


if not getenv("INCLUDE_NETWORK_TESTS"):
    socket.socket = guard
