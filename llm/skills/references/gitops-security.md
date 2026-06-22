# GitOps & Version Control OPSEC

## Git Commit History Exposure

Git commit history is the #1 source of identity leaks for developers. Every commit contains:
- Author name + email (often real identity)
- Timestamps (timezone disclosure)
- Full file diffs (potential secrets)
- Branch/tag names (internal project codenames)

### Self-Audit Commands

```bash
# Check exposed email in public repos
gh api user/repos --paginate -q '.[].full_name' | \
  xargs -I{} gh api repos/{}/commits --paginate -q '.[].commit.author.email' | \
  sort -u

# Find commits with potential secrets (basic patterns)
git log -p --all -S 'password' -S 'secret' -S 'api_key' -S 'token' --source

# Check GitHub Events API for emails
curl -s https://api.github.com/users/<handle>/events/public | \
  jq -r '.[].payload.commits[].author.email' | sort -u
```

### Remediation

1. **Rewrite public history** (nuclear option — only for truly sensitive leaks):
   ```bash
   git filter-repo --mailmap <your-anonymous-email> --path <file-with-secret>
   ```
   Then force-push. Warn collaborators.

2. **Email normalization** (preferred for ongoing):
   - Set GitHub noreply: `gh api user --method PATCH -f noreply=true`
   - Update local git config: `git config user.email "<handle>@users.noreply.github.com"`
   - Use `--committer-date-is-author-date` when amending public commits

3. **Secret rotation**: Any secret found in git history must be rotated immediately. History rewriting does not remove the secret from GitHub's copy.

4. **Pre-commit hooks**:
   ```bash
   # Block commits with common secret patterns
   cat > .git/hooks/pre-commit << 'EOF'
   #!/bin/bash
   if git diff --cached --name-only | xargs grep -l -E '(password|secret|api_key|token)\s*='; then
     echo "BLOCKED: Potential secret in staged changes"
     exit 1
   fi
   EOF
   chmod +x .git/hooks/pre-commit
   ```

### Git-Specific Attack Vectors

| Vector | Risk | Mitigation |
|--------|------|------------|
| Public repo commit emails | Real identity linked to handle | Use noreply GitHub email |
| Commit timestamps | Timezone/location disclosure | Set GIT_AUTHOR_DATE uniformly |
| `.git` directory exposed on web server | Full repo download | Deny access in web server config |
| CI/CD logs showing `git clone` | Internal repo URLs | Use private runners or masked env vars |
| Force-push rewriting | History loss, broken forks | Guard with branch protection rules |
