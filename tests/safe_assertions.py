"""Raise test failures without pytest formatting credential-bearing operands."""


def require(condition, message="Backend invariant failed"):
    if not condition:
        raise AssertionError(message)
