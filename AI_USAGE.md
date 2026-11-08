# AI usage: dsc26-cyb-w04

## Tools

I used ChatGPT to understand the task requirements, implement the Python functions in `triage/core.py`, and implement the command-line interface in `triage/__main__.py`.

I also used ChatGPT to understand Python errors, review test results, and troubleshoot the implementation.

## What AI got wrong

AI initially focused on the public tests when checking the implementation. However, passing the public tests did not verify that the command-line interface worked.

I noticed this by inspecting `triage/__main__.py` and finding that it still contained `raise NotImplementedError`. I implemented the CLI and verified it by running the program with the provided fixture files.

## In my own words

1. Bandit rates the MD5 in `etag()` HIGH and `DB_PASSWORD` LOW. Which would you fix first in Diwan's code, and why?

I would fix DB_PASSWORD first because exposing a database password could allow attackers to access the database and steal sensitive information. The MD5 in etag() may only be used for caching, not for security.

2. Why does a suppression need an expiry date?

A suppression needs an expiry date because it should not hide a security issue forever. When it expires, the team must review the issue again to make sure it is fixed or still needs attention.