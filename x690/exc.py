"""
This module contains exceptions for the x.690 protocol
"""


class X690Error(Exception):
    """
    Top-Level exception for everything related to the X690 protocol
    """


class UnexpectedType(X690Error):
    """
    Raised when decoding resulted in an unexpected type.
    """


class IncompleteDecoding(X690Error):
    """
    Raised when decoding did not consume all bytes.

    The junk bytes are stored in the "remainder" attribute
    """

    def __init__(self, message: str, remainder: bytes) -> None:
        super().__init__(message)
        self.remainder = remainder


class InvalidValueLength(ValueError):
    """
    This error is raised when a value when the length information in the header
    of a "TLV" value does not match the actual value length.

    A likely scenario for this to happen is for example if an IO-operation
    ended prematurely. For example, if the UDP buffer size is too small and the
    remote device returns a packet larger than the buffer.
    """
