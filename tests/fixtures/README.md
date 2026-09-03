# Parser fixtures

These fixtures are sanitized, deterministic protocol inputs used by parser and
normalization tests. They are deliberately small: no live credentials, cookies,
private addresses, or full production responses belong here.

When a parser changes, update the smallest relevant fixture and its assertion so
the behavioral contract remains reviewable.
