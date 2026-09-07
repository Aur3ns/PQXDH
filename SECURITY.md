# Security policy

PQXDH is experimental cryptographic software. It has not received an
independent security audit and must not be treated as a drop-in replacement for
Signal's production implementation.

Please report suspected vulnerabilities privately through GitHub's private
vulnerability reporting feature. Do not include secrets, private keys, or real
message contents in a report.

The project aims to keep secret-dependent comparisons constant-time where the
underlying libraries support it and to erase short-lived secrets after use.
Those measures do not constitute a complete side-channel or implementation
security review.
