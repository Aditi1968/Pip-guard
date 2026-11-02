"""Fixture: hangs at import so the import timeout fires."""

import time

time.sleep(999)
