# dlltools

A lightweight CLI for poking around inside Windows binaries (`.dll` and `.exe`). I built this because I wanted a fast way to check things like entropy and security flags without opening a heavy GUI.

### Quick Start
```bash
# See everything at a glance
dlltools inspect myapp.exe

# Check security features (ASLR, DEP, etc.)
dlltools security myapp.exe

# Export results to JSON for scripting
dlltools imports myapp.exe --json
```

### What it does
- **PE Analysis:** Headers, sections, and resource enumeration.
- **Security Audit:** Quickly check for ASLR, DEP, and CFG.
- **Entropy Calc:** Find packed or encrypted sections easily.


### Building
You'll need VS 2022 (v19.34+) and CMake.
```bash
cmake --preset release
cmake --build --preset release
```

