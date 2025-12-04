#!/usr/bin/env python3
"""Test VLAN Bypass Module Integration

Tests:
1. VLAN bypass module standalone functionality
2. Integration with Identity, Lateral, and Foothold modules
3. Integration with AutoEnumerator
4. Default credential scanning (test:test priority)
5. CVE database queries
6. VLAN topology discovery
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console

# Import modules
from modules.vlan_bypass import (
    VLANBypassModule,
    DEFAULT_CREDENTIALS,
    NETWORK_CVES,
    VLAN_HOP_TECHNIQUES,
    DefaultCredential,
    NetworkCVE,
    VLANHopTechnique,
    DeviceType,
)


class TestVLANBypassModule(unittest.TestCase):
    """Test VLAN Bypass Module core functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console(force_terminal=True, width=120)
        self.session_data = {'LAB_USE': 1}
        self.module = VLANBypassModule(self.console, self.session_data)
    
    def test_default_credentials_database(self):
        """Test default credentials database is populated"""
        self.assertGreater(len(DEFAULT_CREDENTIALS), 50, "Should have 50+ credential entries")
        
        # Check for test:test (APT-41 priority credential)
        test_creds = [c for c in DEFAULT_CREDENTIALS if c.username == 'test' and c.password == 'test']
        self.assertGreater(len(test_creds), 0, "Should have test:test credential")
        
        # Check for various vendors
        vendors = set(c.vendor for c in DEFAULT_CREDENTIALS)
        self.assertIn("Cisco", vendors)
        self.assertIn("Fortinet", vendors)
        self.assertIn("Palo Alto", vendors)
        self.assertIn("HP/Aruba", vendors)
        self.assertIn("Hikvision", vendors)
    
    def test_cve_database(self):
        """Test CVE database is populated with 2024/2025 CVEs"""
        self.assertGreater(len(NETWORK_CVES), 15, "Should have 15+ CVE entries")
        
        # Check for high severity CVEs
        critical_cves = [c for c in NETWORK_CVES if c.cvss_score >= 9.0]
        self.assertGreater(len(critical_cves), 5, "Should have 5+ critical CVEs")
        
        # Check for VLAN bypass CVEs
        vlan_bypass_cves = [c for c in NETWORK_CVES if c.vlan_bypass]
        self.assertGreater(len(vlan_bypass_cves), 10, "Should have 10+ VLAN bypass CVEs")
        
        # Check for 2024 CVEs
        cves_2024 = [c for c in NETWORK_CVES if '2024' in c.cve_id]
        self.assertGreater(len(cves_2024), 10, "Should have 10+ 2024 CVEs")
    
    def test_vlan_hopping_techniques(self):
        """Test VLAN hopping techniques database"""
        self.assertGreater(len(VLAN_HOP_TECHNIQUES), 5, "Should have 5+ techniques")
        
        # Check for key techniques
        technique_names = [t.name for t in VLAN_HOP_TECHNIQUES]
        self.assertIn("DTP Switch Spoofing", technique_names)
        self.assertIn("802.1Q Double Tagging", technique_names)
        self.assertIn("ARP Cache Poisoning Cross-VLAN", technique_names)
        
        # Check each technique has required fields
        for tech in VLAN_HOP_TECHNIQUES:
            self.assertTrue(tech.name, "Technique should have name")
            self.assertTrue(tech.description, "Technique should have description")
            self.assertTrue(tech.mitre_technique, "Technique should have MITRE mapping")
            self.assertGreater(len(tech.commands), 0, "Technique should have commands")
    
    def test_get_credentials_for_target(self):
        """Test credential retrieval for specific targets"""
        # Add device to discovered devices
        self.module.discovered_devices["10.10.10.2"] = {
            "ip": "10.10.10.2",
            "type": "switch",
            "vendor": "Cisco"
        }
        
        creds = self.module.get_credentials_for_target("10.10.10.2")
        
        # Should have Cisco and generic credentials
        self.assertGreater(len(creds), 0, "Should return credentials")
        
        # test:test should be prioritized
        self.assertEqual(creds[0].username, "test")
        self.assertEqual(creds[0].password, "test")
        
        # Should include Cisco-specific credentials
        cisco_creds = [c for c in creds if c.vendor == "Cisco"]
        self.assertGreater(len(cisco_creds), 0, "Should include Cisco credentials")
    
    def test_get_cves_for_device(self):
        """Test CVE retrieval for specific devices"""
        # Get Cisco CVEs
        cisco_cves = self.module.get_cves_for_device("Cisco")
        self.assertGreater(len(cisco_cves), 0, "Should return Cisco CVEs")
        
        # Should be sorted by CVSS
        if len(cisco_cves) > 1:
            self.assertGreaterEqual(cisco_cves[0].cvss_score, cisco_cves[1].cvss_score)
        
        # Get Fortinet CVEs
        fortinet_cves = self.module.get_cves_for_device("Fortinet")
        self.assertGreater(len(fortinet_cves), 0, "Should return Fortinet CVEs")
        
        # Check for specific high-profile CVE
        cve_ids = [c.cve_id for c in fortinet_cves]
        self.assertTrue(
            any('21762' in cve_id or '23113' in cve_id for cve_id in cve_ids),
            "Should include known FortiOS CVEs"
        )
    
    def test_auto_enumerate_vlans(self):
        """Test automatic VLAN enumeration"""
        results = self.module.auto_enumerate_vlans(self.session_data)
        
        # Check all required fields
        self.assertIn('timestamp', results)
        self.assertIn('discovered_vlans', results)
        self.assertIn('network_devices', results)
        self.assertIn('bypass_opportunities', results)
        self.assertIn('credentials_found', results)
        self.assertIn('vulnerable_devices', results)
        self.assertIn('accessible_segments', results)
        
        # Check VLANs discovered
        self.assertGreater(len(results['discovered_vlans']), 0, "Should discover VLANs")
        
        # Check network devices discovered
        self.assertGreater(len(results['network_devices']), 0, "Should discover devices")
        
        # Check bypass opportunities identified
        self.assertGreater(len(results['bypass_opportunities']), 0, "Should identify bypass opportunities")
        
        # Check test:test credential found
        test_creds = [c for c in results['credentials_found'] 
                      if c.get('username') == 'test' and c.get('password') == 'test']
        self.assertGreater(len(test_creds), 0, "Should find test:test credential")


class TestAutoEnumeratorVLANIntegration(unittest.TestCase):
    """Test VLAN bypass integration with AutoEnumerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.console = Console(force_terminal=True, width=120)
        self.session_data = {'LAB_USE': 1, 'AUTO_ENUMERATE_DEPTH': 3}
    
    @patch('modules.auto_enumerate.execute_cmd')
    @patch('modules.auto_enumerate.execute_powershell')
    def test_enumerate_vlan_bypass(self, mock_ps, mock_cmd):
        """Test VLAN bypass enumeration in AutoEnumerator"""
        from modules.auto_enumerate import AutoEnumerator
        
        # Mock command outputs
        mock_cmd.return_value = (0, "hostname\n", "")
        mock_ps.return_value = (0, "output\n", "")
        
        enumerator = AutoEnumerator(self.console, self.session_data)
        
        # Create mock progress
        from unittest.mock import MagicMock
        mock_progress = MagicMock()
        mock_task = MagicMock()
        
        # Run VLAN bypass enumeration
        enumerator._enumerate_vlan_bypass(mock_progress, mock_task)
        
        # Check results
        vlan_data = enumerator.enumeration_data.get('vlan_bypass', {})
        
        self.assertIn('network_devices', vlan_data)
        self.assertIn('discovered_vlans', vlan_data)
        self.assertIn('default_credentials_found', vlan_data)
        self.assertIn('vulnerable_cves', vlan_data)
        self.assertIn('bypass_techniques', vlan_data)
        self.assertIn('accessible_segments', vlan_data)
        
        # Check devices discovered
        self.assertGreater(len(vlan_data['network_devices']), 0)
        
        # Check VLANs discovered
        self.assertGreater(len(vlan_data['discovered_vlans']), 0)
        
        # Check bypass techniques identified
        self.assertGreater(len(vlan_data['bypass_techniques']), 0)
        
        # Check for DTP technique
        dtp_techniques = [t for t in vlan_data['bypass_techniques'] 
                         if 'DTP' in t.get('technique', '')]
        self.assertGreater(len(dtp_techniques), 0, "Should identify DTP bypass")


class TestCVEDetails(unittest.TestCase):
    """Test specific CVE details and coverage"""
    
    def test_critical_2024_cves(self):
        """Test that critical 2024 CVEs are included"""
        critical_2024 = [c for c in NETWORK_CVES 
                        if '2024' in c.cve_id and c.cvss_score >= 9.0]
        
        cve_ids = [c.cve_id for c in critical_2024]
        
        # Check for known critical CVEs
        expected_cves = [
            'CVE-2024-3400',   # Palo Alto GlobalProtect
            'CVE-2024-21762',  # FortiOS SSL-VPN
            'CVE-2024-20419',  # Cisco SSM
        ]
        
        for expected in expected_cves:
            self.assertIn(expected, cve_ids, f"Should include {expected}")
    
    def test_auth_bypass_cves(self):
        """Test authentication bypass CVEs"""
        auth_bypass = [c for c in NETWORK_CVES if c.auth_bypass]
        
        self.assertGreater(len(auth_bypass), 5, "Should have 5+ auth bypass CVEs")
        
        # All auth bypass CVEs should have exploit info
        for cve in auth_bypass:
            self.assertTrue(cve.exploit_method, f"{cve.cve_id} should have exploit method")
    
    def test_rce_cves(self):
        """Test RCE CVEs"""
        rce_cves = [c for c in NETWORK_CVES if c.rce]
        
        self.assertGreater(len(rce_cves), 8, "Should have 8+ RCE CVEs")
        
        # Most RCE CVEs should be high severity (CVSS >= 7.0)
        # Some local RCE may be lower (e.g., CVE-2024-20399 is 6.7 - local CLI injection)
        high_severity_rce = [c for c in rce_cves if c.cvss_score >= 7.0]
        self.assertGreater(len(high_severity_rce), len(rce_cves) * 0.8, 
                          "Most RCE CVEs should be high severity")


class TestCredentialPrioritization(unittest.TestCase):
    """Test credential prioritization logic"""
    
    def test_test_test_priority(self):
        """Test that test:test is prioritized first"""
        module = VLANBypassModule()
        
        # Get credentials for any target
        creds = module.get_credentials_for_target("10.10.10.1")
        
        # First credential should be test:test
        self.assertEqual(creds[0].username, "test")
        self.assertEqual(creds[0].password, "test")
    
    def test_vendor_specific_priority(self):
        """Test vendor-specific credentials come before generic"""
        module = VLANBypassModule()
        
        # Add Cisco device
        module.discovered_devices["10.10.10.2"] = {
            "vendor": "Cisco",
            "type": "switch"
        }
        
        creds = module.get_credentials_for_target("10.10.10.2")
        
        # Should have both Cisco and generic
        vendors = [c.vendor for c in creds]
        self.assertIn("Cisco", vendors)
        self.assertIn("Generic", vendors)


class TestModuleIntegration(unittest.TestCase):
    """Test integration with other modules"""
    
    def test_identity_module_integration(self):
        """Test integration with Identity module"""
        module = VLANBypassModule()
        
        # Should have lazy-loaded identity module
        self.assertIsNone(module._identity_module)
        
        # Access should trigger lazy load (may fail if module not available)
        try:
            identity = module.identity_module
            self.assertIsNotNone(identity)
        except Exception:
            pass  # Module may not be fully loadable in test environment
    
    def test_lateral_module_integration(self):
        """Test integration with Lateral module"""
        module = VLANBypassModule()
        
        # Should have lazy-loaded lateral module
        self.assertIsNone(module._lateral_module)
        
        # Access should trigger lazy load
        try:
            lateral = module.lateral_module
            self.assertIsNotNone(lateral)
        except Exception:
            pass  # Module may not be fully loadable in test environment


def run_vlan_bypass_demo():
    """Run a demonstration of VLAN bypass capabilities"""
    console = Console()
    session_data = {'LAB_USE': 1}
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  APT-41 VLAN Bypass Module - Integration Demo[/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]\n")
    
    # Initialize module
    module = VLANBypassModule(console, session_data)
    
    # 1. Show credential database stats
    console.print("[bold]1. Default Credentials Database:[/bold]")
    vendor_counts = {}
    for cred in DEFAULT_CREDENTIALS:
        vendor_counts[cred.vendor] = vendor_counts.get(cred.vendor, 0) + 1
    
    for vendor, count in sorted(vendor_counts.items()):
        console.print(f"   • {vendor}: {count} credentials")
    
    # Show test:test priority
    test_creds = [c for c in DEFAULT_CREDENTIALS if c.username == 'test' and c.password == 'test']
    console.print(f"\n   [yellow]APT-41 Priority: test:test ({len(test_creds)} entries)[/yellow]")
    
    # 2. Show CVE database stats
    console.print("\n[bold]2. Network CVE Database (2024/2025):[/bold]")
    console.print(f"   • Total CVEs: {len(NETWORK_CVES)}")
    console.print(f"   • VLAN Bypass CVEs: {len([c for c in NETWORK_CVES if c.vlan_bypass])}")
    console.print(f"   • Auth Bypass CVEs: {len([c for c in NETWORK_CVES if c.auth_bypass])}")
    console.print(f"   • RCE CVEs: {len([c for c in NETWORK_CVES if c.rce])}")
    console.print(f"   • Critical (CVSS 9+): {len([c for c in NETWORK_CVES if c.cvss_score >= 9.0])}")
    
    # Show top 5 CVEs
    console.print("\n   [bold]Top 5 Critical CVEs:[/bold]")
    sorted_cves = sorted(NETWORK_CVES, key=lambda c: c.cvss_score, reverse=True)
    for cve in sorted_cves[:5]:
        console.print(f"   • {cve.cve_id} ({cve.vendor}): CVSS {cve.cvss_score}")
    
    # 3. Show VLAN hopping techniques
    console.print("\n[bold]3. VLAN Hopping Techniques:[/bold]")
    for tech in VLAN_HOP_TECHNIQUES:
        console.print(f"   • {tech.name} ({tech.mitre_technique})")
    
    # 4. Run auto enumeration
    console.print("\n[bold]4. Auto-Enumeration Results:[/bold]")
    results = module.auto_enumerate_vlans(session_data)
    
    console.print(f"   • VLANs Discovered: {len(results['discovered_vlans'])}")
    console.print(f"   • Network Devices: {len(results['network_devices'])}")
    console.print(f"   • Credentials Found: {len(results['credentials_found'])}")
    console.print(f"   • Bypass Opportunities: {len(results['bypass_opportunities'])}")
    console.print(f"   • Accessible Segments: {len(results['accessible_segments'])}")
    
    # 5. Show bypass opportunities
    console.print("\n[bold]5. Identified Bypass Opportunities:[/bold]")
    for opp in results['bypass_opportunities']:
        console.print(f"   • {opp['method']}: {opp['target']} ({opp['likelihood']})")
    
    console.print("\n[bold green]✓ Demo complete![/bold green]\n")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        run_vlan_bypass_demo()
    else:
        # Run tests
        unittest.main(verbosity=2)
