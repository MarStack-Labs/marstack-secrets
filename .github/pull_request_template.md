## What changed, and why

The diff says what. Explain why, and what would have gone wrong without it.

## Checklist

- [ ] `make check` passes locally, including `arch-check` and `drill`
- [ ] No comments added to any file, in any language
- [ ] New behaviour arrives with a test; new security behaviour with a test I have watched fail
- [ ] Documents that describe the changed behaviour are updated in this same commit
- [ ] A new dependency, if any, comes with an ADR
- [ ] Anything deliberately not built is recorded rather than left implicit
- [ ] Commit messages explain why, contain no AI attribution, and are in English

## If a test caught something

Say so. A design flaw found by a test is the most useful thing a reviewer can read.
