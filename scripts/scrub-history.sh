#!/usr/bin/env bash
# Scrub all references to REDACTED from git history.
#
# DESTRUCTIVE: rewrites every commit SHA from ba2a918 forward and
# requires `git push --force` to overwrite the public main branch.
# This breaks anyone who has cloned/forked the repo and invalidates
# every existing commit-SHA reference (PRs, issues, external links).
#
# Prereqs:
#   pip install git-filter-repo   (or `brew install git-filter-repo`)
#
# Run from repo root. Review the diff, then force-push manually:
#   git push --force-with-lease origin main
#
set -euo pipefail

if ! command -v git-filter-repo >/dev/null 2>&1; then
  echo "git-filter-repo not installed. brew install git-filter-repo" >&2
  exit 1
fi

# Backup current ref before rewrite
git update-ref refs/backup/pre-scrub-main refs/heads/main

# 1. Rewrite author/committer emails
cat > /tmp/overwatch-mailmap <<'EOF'
professor-moody <keys@nimbus.lan> <keys@nimbus.lan>
professor-moody <keys@nimbus.lan> professor-moody <keys@nimbus.lan>
EOF
git filter-repo --force --mailmap /tmp/overwatch-mailmap

# 2. Scrub commit message + blob contents
cat > /tmp/overwatch-replacements.txt <<'EOF'
registry.npmjs.org==>registry.npmjs.org
registry.npmjs.org==>registry.npmjs.org
keys@nimbus.lan==>keys@nimbus.lan
example.invalid==>example.invalid
REDACTED==>REDACTED
REDACTED==>REDACTED
professor-moody==>professor-moody
EOF
git filter-repo --force --replace-text /tmp/overwatch-replacements.txt

echo
echo "History rewritten. Verify with:"
echo "  git log --all --format='%h %ae %an %s' | grep -i REDACTED || echo CLEAN"
echo "  git log --all -p -S REDACTED | head"
echo
echo "When satisfied, force-push:"
echo "  git remote add origin https://github.com/professor-moody/overwatch.git  # if filter-repo dropped it"
echo "  git push --force-with-lease origin main"
echo
echo "Backup of old main is at refs/backup/pre-scrub-main"
