---
name: Autonomous testing
description: When user says "test this", run all verification autonomously via CLI/API/curl — don't ask user to manually test in browser
type: feedback
---

When the user says "test this" or "let's test", run ALL verification autonomously — including frontend behavior testing via API calls, WebSocket tests, curl requests, etc. Do NOT ask the user to open a browser, click things, or manually verify. The human-in-the-loop aspect slows things down and prevents quick debugging.

**Why:** User found that asking them to manually test in the browser was slow and unhelpful. Autonomous CLI-based testing catches issues faster and allows rapid iteration.

**How to apply:** After making changes, verify end-to-end via:
- REST API calls (curl) for server behavior
- WebSocket connections (python websocket) for WS functionality
- Check server logs for errors
- Verify process states (tasklist, netstat)
- Only involve the user for final visual confirmation after all automated checks pass
