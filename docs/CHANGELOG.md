# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2024

### Added
- Initial release of Windows Lateral Movement Simulation TUI
- 11 integrated modules covering all phases of lateral movement
- APT-41 TTP alignment throughout all modules
- MITRE ATT&CK framework integration
- Auto-enumeration mode with lateral movement
- LogHunter integration for log analysis
- Windows Moonwalk with fake log entry injection
- LOLBins reference database with dynamic command builders
- MADCert integration for certificate generation
- LLM Remote Agent with MEMSHADOW MRAC protocol
- Comprehensive reporting (TXT, JSON, HTML)
- Self-contained installation scripts (run.bat, run.sh)
- Complete documentation

### Features
- **Foothold Module**: Initial access assessment
- **Orientation Module**: Local environment understanding
- **Identity Module**: Credential harvesting and domain context
- **Lateral Movement Module**: SMB, WinRM, WMI, RDP pivoting
- **Consolidation Module**: Persistence and strategic objectives
- **OPSEC Module**: Defense evasion and operational security
- **LLM Agent Module**: Self-coding remote execution agent
- **MADCert Module**: Certificate generation for AD environments
- **LOLBins Module**: Living Off The Land Binaries reference
- **LogHunter Module**: Windows event log analysis
- **Moonwalk Module**: Advanced log clearing with evasion

### Security
- LAB_USE mode for safe testing (default: enabled)
- No online dependencies
- Self-contained tool
- Comprehensive OPSEC considerations

### Documentation
- Complete README with usage examples
- Installation guide (INSTALL.md)
- Module-specific documentation
- Code comments and docstrings

---

**For authorized security testing only.**
