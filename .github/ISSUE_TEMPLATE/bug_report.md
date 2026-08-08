---
name: Test Suite
about: Report issues with test failures, edge cases, or new detection features
title: "[BUG/FEATURE]"
labels: bug, feature, triage
body:
  - type: textarea
    attributes:
      label: Problem Description
      description: Describe the issue or feature request
      placeholder: "What's not working or what's missing?"
    validations:
      required: true

  - type: textarea
    attributes:
      label: Sample Payload (if applicable)
      description: Provide a minimal package.json or lockfile snippet that triggers the issue
      render: yaml
    validations:
      required: false

  - type: input
    attributes:
      label: Operating System
      description: e.g., Ubuntu 22.04, macOS Sonoma, Windows 11
    validations:
      required: false
---
