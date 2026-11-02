"""Fixture: a quiet target whose dependency ships a noisy .pth (attribution, PRD M2)."""

import fx_noisy_dep  # noqa: F401  (the dependency module itself is quiet)
