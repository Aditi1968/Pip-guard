"""Fixture (benign): base64-decodes a data blob and never executes it."""

import base64
import json

CONFIG = json.loads(base64.b64decode("eyJyZXRyaWVzIjogM30="))
