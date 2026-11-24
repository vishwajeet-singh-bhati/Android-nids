"""SMS scam detection module.

The detector is deliberately independent of the Llama explanation layer: it
classifies an SMS into ham / spam / smishing, produces calibrated scores,
stable evidence codes and safe action codes. Llama only explains this result.
"""

from __future__ import annotations

__version__ = "0.1.0"
