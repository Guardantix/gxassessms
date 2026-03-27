"""Policy engine -- pure functions that consume reference tables and produce decisions.

Policy modules NEVER do I/O. YAML rule files are loaded by config/ and injected
as plain dicts. Each policy module defines a Protocol for its extension point
and ships a default implementation.

Three policy tiers:
1. Reference tables (YAML) -- pure data, no branching logic
2. Deterministic policy functions (Python) -- side-effect-free, consume reference tables
3. Policy recommendations (AI/analytics) -- never auto-applied (separate plans)
"""
