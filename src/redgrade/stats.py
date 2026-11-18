"""Small statistics helpers shared by the baseline comparison and the scorecard."""

from math import sqrt

Z_95 = 1.96


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Behaves well with the tiny trial counts used in CI (3-10): unlike the normal
    approximation it never collapses to a zero-width interval at 0% or 100%.
    ``n == 0`` returns the uninformative interval ``(0, 1)``.
    """
    if n <= 0:
        return 0.0, 1.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)
