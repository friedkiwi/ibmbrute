# Persistent Instructions

- Commit after each major feature or logical change.
- Push immediately after each commit.
- Keep session/resume behavior enabled by default unless the user explicitly opts out.
- Default multithreaded cracking to one thread per detected CPU core when `--mt` is omitted.
- Print a startup engine banner that names the cracking engine and thread count.
- Default `--engine auto` to Metal when Metal support is compiled in; otherwise use mt.
- Keep `--engine mt|metal|auto` selection wired into startup reporting and session identity.
- If Metal is selected, print a TODO noting that the Metal kernel is not implemented yet.
- Prefer small, reviewable changes with verification after each feature.
- Preserve user-created working notes unless the user asks to track them.
