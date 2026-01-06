# Standard finding structure

from dataclasses import dataclass

@dataclass
class Finding:
    dtype: str
    value: str
    masked_value: str
    severity: str
    confidence: int
    context: str
    direction: str
    action: str = None


