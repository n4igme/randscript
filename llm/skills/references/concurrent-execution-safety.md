# Concurrent Execution Safety

Guidelines for running multiple agents or parallel workflows against the same engagement.

## State Conflicts

- `state.yaml` is not atomic — serialize `advance_phase` and `add_finding` calls
- Use file lock if running multiple agents: `with open(state_path + '.lock', 'w') as lock:`
- Temp files: use `{finding-id}-{timestamp}.tmp` to avoid collisions

## Parallel Scanning

- Run independent targets in parallel (different directories per target)
- Share evidence via `../{skill}-output/evidence/` symlinks or copies
- Rate-limit flagging: after 3 blocked payloads across workers, pause all

## Subagent Handoff

- Document phase status before spawning subagents (state.yaml must be consistent)
- Subagents read state only — they should not advance phases or write findings directly
- Parent agent validates subagent output before marking phase PASSED
