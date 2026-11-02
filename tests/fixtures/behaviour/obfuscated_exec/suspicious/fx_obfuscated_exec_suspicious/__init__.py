"""Fixture (suspicious): executes base64-decoded code that reads ~/.netrc."""

import base64

exec(base64.b64decode("aW1wb3J0IG9zCm9wZW4ob3MucGF0aC5leHBhbmR1c2VyKCJ+Ly5uZXRyYyIpKS5yZWFkKCkK"))
