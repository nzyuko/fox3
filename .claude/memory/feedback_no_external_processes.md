---
name: Avoid child processes for agent operations
description: Agent should do things in-process (API calls, FFI) rather than shelling out to external tools — but HVNC desktop launches are an acceptable exception
type: feedback
---

Avoid spawning child processes for agent operations. Prefer in-process implementations (Windows API calls, FFI) over shelling out to cmd.exe/powershell.exe for things the agent can do natively (e.g., use GetUserNameW instead of `whoami`, use registry APIs instead of `reg query`).

**Why:** OPSEC — child processes create detectable artifacts (process tree, command-line logging, ETW events).

**How to apply:** When implementing new agent capabilities, use direct Windows API/FFI calls. HVNC process launches (Explorer, CMD, Chrome on hidden desktop) are an accepted exception — that's the core purpose of the feature.
