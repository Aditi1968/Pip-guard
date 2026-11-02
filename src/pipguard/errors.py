"""Exception types shared across stages. Any of these maps to an ``error`` verdict."""


class PipGuardError(Exception):
    """Base class: a stage could not do its job. Never swallowed into ``allow``."""


class InvalidSpecError(PipGuardError):
    """The requirement is not an exact ``name==version`` pin."""


class FetchError(PipGuardError):
    """PyPI lookup or download failed, or no usable artifact exists."""


class HashMismatchError(FetchError):
    """A downloaded file does not match the SHA-256 published by PyPI (FR-2.2)."""


class ExtractionError(PipGuardError):
    """An archive violated a safe-extraction rule (FR-2.3)."""


class SandboxError(PipGuardError):
    """The container could not be run (as opposed to the package misbehaving)."""


class PolicyError(PipGuardError):
    """Dynamic analysis was refused by the FR-4.10 policy guard."""
