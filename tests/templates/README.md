# Template fixtures

These `.bline` files are safe local fixtures for manually exercising the Template System.

- `hello.bline` uses only the safe built-in CLT runtime actions and can be loaded, selected, and run today.
- `evidence-review.bline` is another runnable template that demonstrates a nested operation and flows.
- `web-audit.bline` and `ssh-review.bline` are valid operational workflow definitions. They load and compile, but require explicit Blackline capability adapters before they can run tool actions.
- `clt-language-showcase.bline` compiles every construct currently implemented by CLT: comments, assignments, literals, operations, inputs/options, flows, semantic conditions in flexible order, indentation, and `else`.

The language words `and`, `or`, `not`, and `is` remain reserved for later work; they are deliberately not used in the valid showcase because the v0 parser does not implement compound logic yet.
