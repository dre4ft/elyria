# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Grey Team — Passive OSINT reconnaissance module.

Domain-focused passive intelligence gathering with minimal target interaction.
Phase 1 collects maximum data deterministically (DNS, WHOIS, SSL, crt.sh,
HTTP headers, frontend code, Wayback, GitHub/Google dorks).
Phase 2 uses AI only for refinement, correlation, and attack chain analysis,
with optional sandbox shell for passive OSINT CLI tools (dig, whois, curl).
"""