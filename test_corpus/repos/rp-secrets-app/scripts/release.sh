#!/bin/sh
set -e
GITHUB_TOKEN={{secret:github_pat:app4}}
gh release create "$1" --notes-file CHANGELOG.md
