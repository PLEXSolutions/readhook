# Roadmap
This is a rough roadmap for the project.

## v1: Current version
This is the first 'get up and running' version. As a result, many aspects are either hard coded or bundled together.

## v1.1: Re-factor
This iteration splits out the payload analysis and generation code (fullhook.so) from the synthetic vulnerability (basehook.so).

## v2: Auto-generation of payloads
In this release, we will use the EnVizen project (https://github.com/polyverse/binary-entropy-visualizer) to automatically create payloads.

## v3: Configurable vulnerabilities
Make it easier to exploit different types of vulnerabilities (e.g. use after free, etc.) versus a standard buffer overflow.
