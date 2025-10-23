# utils/string_matcher
import difflib
from typing import List, Optional


def typo_match(user_input: str, candidates: List[str], cutoff: float = 0.6, n: int = 1) -> Optional[List[str]]:
    user_input = user_input.strip().lower()
    if not user_input or not candidates:
        return None

    candidate_map = {c.lower(): c for c in candidates}
    matches = difflib.get_close_matches(user_input, candidate_map.keys(), n=n, cutoff=cutoff)

    if matches:
        return [candidate_map[m] for m in matches]
    return None
