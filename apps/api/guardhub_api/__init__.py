"""GuardHub API package — orchestration brain (GUARDHUB_STANDARDS §3, §7.1).

Decides *what* to scan and turns raw scanner findings into plain language. Never probes targets
itself: all network egress to customer targets goes through the Go scanner.
"""
