# Threat Rules Repository

## Overview
Detection and hunting content to support digital forensics, malware analysis, and incident response programs.

## Repository Structure
```
.
├── LICENSE
├── README.md
├── reports          # Supporting analysis material and guidance
├── edr              # Endpoint detection rules (emerging, generic, hunting / inspired by Sigma)
│   ├── emerging
│   ├── generic
│   └── hunting
├── sigma            # Sigma detections across maturity levels
│   ├── emerging
│   ├── generic
│   └── hunting
├── snort            # Snort compatible signatures
│   ├── emerging
│   ├── generic
│   └── hunting
└── yara             # YARA rules for malware and artifact detection
│   ├── emerging
│   ├── generic
│   └── hunting
```

## Contributing
Contributions are welcome.
Please open a pull request with a description.

## Confidentiality
I use the Traffic Light Protocol to determine what can be shared publicly.
Content will be updated or redacted if the classification changes.
If you suspect that the content exceeds the sharing scope, please contact me.