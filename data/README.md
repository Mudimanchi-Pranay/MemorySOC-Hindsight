# MemorySOC Demo Data

The incidents in this POC are synthetic and intentionally designed to create recurring SOC patterns.

The golden demo pattern is:

- INC-1001: encoded PowerShell + external communication -> true positive
- INC-1002: PowerShell in approved admin context -> false positive
- INC-1003: PowerShell + external payload download -> true positive
- NEW-POWER-001: new encoded PowerShell + external destination

The purpose is to demonstrate that Hindsight can retrieve relevant historical context rather than to claim that the synthetic data represents real-world incident frequencies.
