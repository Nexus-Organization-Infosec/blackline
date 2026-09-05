# Templates

Templates are reusable `.bline` files containing CLT source. They are an internal registry-backed system; the lifecycle commands are only thin adapters over that system.

```text
load ./web-audit.bline    # validate and register a user-owned source path
list templates            # discover registrations
use web-audit             # select one active template
edit                      # edit the active source through VISUAL or EDITOR
run                       # execute the active template
```

`load` completes directories and `.bline` files with Tab. When a matching source exists, the `.bline` extension may be omitted: `load web-audit` resolves `web-audit.bline`.

`load` and `use` never execute a template. `run web-audit[target=10.0.0.5]` supports named inputs now, ready for future CLT input declarations.

The registry persists metadata in local Blackline storage while continuing to reference the original source file. It refreshes a source before use, list, or run. If an edit introduces invalid CLT, the current source is marked `invalid` and the in-memory last valid compilation remains executable until the source is fixed. Missing source files remain registered and are shown as `missing`.

Template execution passes compiled IR to CLT's explicit capability runtime. The initial runtime exposes only non-operational declarative verbs (`analyze`, `collect`, `report`, `save`, `load`). Security/tool actions require an explicit Blackline capability adapter; templates never gain implicit execution authority from loading.

Safe test templates are available in [`tests/templates`](/Volumes/SSD/Developer/github/blackline/tests/templates). Start with `hello.bline`; `clt-language-showcase.bline` is the comprehensive parser fixture.
