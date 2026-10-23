"""Below-range applicability evidence: does an advisory apply to an installed
version its stated ranges leave out? This package gathers the facts (candidates,
the fix patch, the installed source, hunk presence); review decides."""

from traust_engine.applicability.candidates import BELOW_RANGE, GAP, Candidate, classify
from traust_engine.applicability.packet import build

__all__ = ["BELOW_RANGE", "GAP", "Candidate", "build", "classify"]
