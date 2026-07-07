# Diagrams

Each diagram in the project README is a pair of hand-drawn SVGs - one for
GitHub's light theme, one for dark - selected with a `<picture>` element.
Within a pair the geometry is identical; only the CSS variable block at the
top of each file differs, so a diff between the two variants shows colors
and nothing else.

`src/` holds the Mermaid definitions the SVGs were drawn from. They are the
readable reference for what each diagram says. If you change a flow, update
the `.mmd` source and both SVG variants together.
