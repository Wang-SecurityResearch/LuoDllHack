# -*- coding: utf-8 -*-
"""
luodllhack/analysis/com_discovery.py

COM GUID Discovery Module - Automatically discovers COM interface information in DLLs

Functions:
    1. Discover registered COM CLSID/IID from the registry
    2. Extract type library information from DLL resource sections
    3. Infer COM interface types from exported functions
    4. Support 7-Zip style CreateObject interface
"""

import struct
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


@dataclass
class GUID:
    """COM GUID Representation"""
    data1: int  # 4 bytes
    data2: int  # 2 bytes
    data3: int  # 2 bytes
    data4: bytes  # 8 bytes

    def __str__(self) -> str:
        """Convert to standard GUID string format"""
        return (f"{{{self.data1:08X}-{self.data2:04X}-{self.data3:04X}-"
                f"{self.data4[0]:02X}{self.data4[1]:02X}-"
                f"{self.data4[2]:02X}{self.data4[3]:02X}"
                f"{self.data4[4]:02X}{self.data4[5]:02X}"
                f"{self.data4[6]:02X}{self.data4[7]:02X}}}")

    def to_c_define(self) -> str:
        """Convert to C DEFINE_GUID format"""
        d4 = ", ".join(f"0x{b:02X}" for b in self.data4)
        return f"0x{self.data1:08X}, 0x{self.data2:04X}, 0x{self.data3:04X}, {d4}"

    @classmethod
    def from_string(cls, guid_str: str) -> 'GUID':
        """Parse GUID from string"""
        # Remove curly braces
        guid_str = guid_str.strip('{}')
        parts = guid_str.split('-')

        data1 = int(parts[0], 16)
        data2 = int(parts[1], 16)
        data3 = int(parts[2], 16)
        data4 = bytes.fromhex(parts[3] + parts[4])

        return cls(data1, data2, data3, data4)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'GUID':
        """Parse GUID from bytes (16 bytes)"""
        data1, data2, data3 = struct.unpack('<IHH', data[:8])
        data4 = data[8:16]
        return cls(data1, data2, data3, data4)


@dataclass
class COMInterfaceInfo:
    """COM Interface Information"""
    name: str
    iid: Optional[GUID] = None
    clsid: Optional[GUID] = None
    methods: List[str] = field(default_factory=list)
    vtable_offset: int = 0  # Offset in vtable
    description: str = ""


@dataclass
class COMClassInfo:
    """COM Class Information"""
    name: str
    clsid: GUID
    progid: str = ""
    dll_path: str = ""
    threading_model: str = "Both"
    interfaces: List[COMInterfaceInfo] = field(default_factory=list)


# Standard COM interface IIDs (defined in Windows SDK)
STANDARD_IIDS = {
    "IUnknown": GUID(0x00000000, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
    "IClassFactory": GUID(0x00000001, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
    "IDispatch": GUID(0x00020400, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
    "IStream": GUID(0x0000000C, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
    "IPersist": GUID(0x0000010C, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
    "IPersistFile": GUID(0x0000010B, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
    "IPersistStream": GUID(0x00000109, 0x0000, 0x0000, bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])),
}


def _get_data_sections(data: bytes) -> List[Tuple[int, int]]:
    """Retrieve data section ranges of a PE file (skipping code sections)"""
    if not HAS_PEFILE:
        # Fallback if pefile is unavailable: return entire file (skipping header)
        return [(0x1000, len(data))]

    try:
        import io
        pe = pefile.PE(data=data)
        sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
            # Data sections: .data, .rdata, .rodata, etc.
            # Skip code section: .text
            if name in ['.data', '.rdata', '.rodata', 'DATA', 'RDATA']:
                start = section.PointerToRawData
                size = section.SizeOfRawData
                if start > 0 and size > 0:
                    sections.append((start, start + size))
        return sections if sections else [(0x1000, len(data))]
    except Exception:
        return [(0x1000, len(data))]


def scan_guids_from_binary(data: bytes, min_offset: int = 0x1000) -> List[GUID]:
    """
    Scan for GUIDs in binary data

    Improved strategy:
    1. Prioritize scanning data sections (.data, .rdata), skip code section (.text)
    2. Collect only prefixes appearing 3+ times (indicating a true GUID table)
    3. Verify that GUIDs with the same prefix have different Data4 (distinguish true GUID tables from code patterns)
    4. Sort by "authenticity"

    Args:
        data: Binary data
        min_offset: Minimum scan offset (skipping PE header)

    Returns:
        List of discovered GUIDs
    """
    # {(Data1, Data2, Data3): [(position, Data4), ...]}
    seen_prefixes = {}

    # Get data section ranges
    data_sections = _get_data_sections(data)

    # First pass: collect candidate GUIDs in data sections only
    for section_start, section_end in data_sections:
        for i in range(section_start, min(section_end, len(data)) - 15, 4):
            try:
                d1, d2, d3 = struct.unpack('<IHH', data[i:i+8])
                d4 = data[i+8:i+16]

                # Filter obviously invalid values
                if d1 == 0 or d1 == 0xFFFFFFFF:
                    continue
                if d1 < 0x10000:  # Too small, likely a constant
                    continue
                if d1 == 0xCCCCCCCC:  # MSVC Debug padding
                    continue
                if d4 == bytes(8):  # All-zero Data4
                    continue

                # Filter ASCII strings (all bytes printable)
                guid_bytes = data[i:i+16]
                if all(0x20 <= b <= 0x7E or b == 0 for b in guid_bytes):
                    continue  # Looks like an ASCII string

                prefix = (d1, d2, d3)
                if prefix not in seen_prefixes:
                    seen_prefixes[prefix] = []
                seen_prefixes[prefix].append((i, d4))
            except Exception:
                pass

    # Second pass: evaluate "authenticity" of each prefix
    # True GUID table: same prefix with multiple different Data4 values
    # Code pattern: same prefix with very similar or repeated Data4 values
    scored_prefixes = []
    for prefix, entries in seen_prefixes.items():
        if len(entries) < 3:
            continue

        # Calculate number of unique Data4 values
        unique_d4 = set(d4 for _, d4 in entries)
        unique_ratio = len(unique_d4) / len(entries)

        # True GUID table should have a high uniqueness ratio
        if unique_ratio < 0.5:
            continue

        # Detect COM GUID structural characteristics
        d1, d2, d3 = prefix
        com_score = 0

        # Check Data4 structure
        sample_d4 = [d4 for _, d4 in entries[:10]]
        if sample_d4:
            # Check for structured Data4 patterns (true GUID table)
            # 1. Check for common suffixes (e.g., ...0000 in 7-Zip, or ...0046 in standard COM)
            common_suffix_len = 0
            for suffix_len in [2, 3, 4]:
                suffixes = set(d4[-suffix_len:] for d4 in sample_d4)
                if len(suffixes) <= 2:  # Suffixes mostly identical
                    common_suffix_len = suffix_len

            if common_suffix_len >= 2:
                com_score += 40  # Common suffix, looks like a GUID table

            # 2. Check for sequential or continuous patterns in varying parts
            varying_parts = [d4[:4] for d4 in sample_d4]
            if len(set(varying_parts)) == len(varying_parts):
                try:
                    values = [int.from_bytes(d4[:4], 'little') for d4 in sample_d4]
                    sorted_values = sorted(values)
                    # Check if nearly sequential
                    if values == sorted_values or len(set(values)) > len(values) * 0.8:
                        com_score += 30
                except:
                    pass

        # Bonus for reasonable Data2/Data3 values
        # Exclude obvious code patterns (common instructions)
        code_d2d3 = {
            0x4850, 0xC183, 0x8B48, 0x4889, 0x8948, 0x458B,  # MOV/PUSH
            0x20EC, 0x28EC, 0x30EC, 0x38EC, 0x40EC, 0x48EC,  # SUB RSP
        }
        if d2 not in code_d2d3 and d3 not in code_d2d3:
            if d2 > 0x1000 and d3 > 0x1000:
                com_score += 30
            elif d2 > 0 and d3 > 0:
                com_score += 10

        # Scoring: COM features prioritized, quantity second
        score = com_score * 1000 + min(len(unique_d4), 100)

        if score > 0:
            scored_prefixes.append((prefix, entries, score))

    # Sort by score descending
    scored_prefixes.sort(key=lambda x: x[2], reverse=True)

    # Collect GUIDs
    guids = []
    seen_guids = set()
    for prefix, entries, _ in scored_prefixes:
        for pos, d4 in entries:
            try:
                guid = GUID.from_bytes(data[pos:pos+16])
                guid_str = str(guid)
                if guid_str not in seen_guids:
                    seen_guids.add(guid_str)
                    guids.append(guid)
            except Exception:
                pass

    return guids


def get_known_iid(name: str) -> Optional[GUID]:
    """Get IID for a standard interface"""
    return STANDARD_IIDS.get(name)


class COMDiscovery:
    """
    COM Interface Discoverer

    Usage:
        discovery = COMDiscovery("C:\\Windows\\System32\\7z.dll")

        # Get all discovered COM info
        info = discovery.discover()

        # Get interface info for a specific method
        interface = discovery.get_interface_for_method("CreateDecoder")
    """

    def __init__(self, dll_path: str):
        self.dll_path = Path(dll_path)
        self.dll_name = self.dll_path.stem
        self.exports: List[str] = []
        self.com_classes: List[COMClassInfo] = []
        self.interfaces: List[COMInterfaceInfo] = []
        self.discovered_guids: List[GUID] = []

    def discover(self) -> Dict[str, Any]:
        """
        Execute full COM discovery process

        Returns:
            Dictionary containing discovered COM information
        """
        result = {
            'dll_path': str(self.dll_path),
            'is_com_dll': False,
            'com_type': None,  # 'standard', 'createobject', etc.
            'exports': [],
            'classes': [],
            'interfaces': [],
            'guids': [],  # GUIDs scanned from binary
            'recommended_init': None,
        }

        # 1. Get exported functions
        self.exports = self._get_exports()
        result['exports'] = self.exports

        # 2. Determine COM DLL type
        if self._has_standard_com_exports():
            result['is_com_dll'] = True
            result['com_type'] = 'standard'
            result['recommended_init'] = 'DllGetClassObject'
        elif self._has_createobject_exports():
            result['is_com_dll'] = True
            result['com_type'] = 'createobject'
            result['recommended_init'] = 'CreateObject'

        # 3. Discover CLSIDs from the registry
        if HAS_WINREG:
            result['classes'] = self._discover_from_registry()

        # 4. Scan for GUIDs from binary
        result['guids'] = self._scan_guids_from_dll()

        # 5. Infer interfaces
        result['interfaces'] = self._infer_interfaces()

        return result

    def _scan_guids_from_dll(self) -> List[str]:
        """Scan for GUIDs in the DLL binary"""
        if not self.dll_path.exists():
            return []

        try:
            with open(self.dll_path, 'rb') as f:
                data = f.read()

            guids = scan_guids_from_binary(data)
            self.discovered_guids = guids

            # De-duplicate and return as string format
            seen = set()
            unique = []
            for g in guids:
                s = str(g)
                if s not in seen:
                    seen.add(s)
                    unique.append(s)

            return unique[:50]  # Limit return count
        except Exception:
            return []

    def _get_exports(self) -> List[str]:
        """Get list of DLL exported functions"""
        if not HAS_PEFILE:
            return []

        try:
            pe = pefile.PE(str(self.dll_path))
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                return [
                    exp.name.decode('utf-8', errors='ignore')
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
                    if exp.name
                ]
        except Exception:
            pass
        return []

    def _has_standard_com_exports(self) -> bool:
        """Check for standard COM exports"""
        standard_exports = {'DllGetClassObject', 'DllCanUnloadNow', 'DllRegisterServer'}
        return bool(standard_exports.intersection(set(self.exports)))

    def _has_createobject_exports(self) -> bool:
        """Check for CreateObject style exports (non-standard COM)"""
        createobject_exports = {'CreateObject', 'GetClassObject'}
        return bool(createobject_exports.intersection(set(self.exports)))

    def _discover_from_registry(self) -> List[Dict]:
        """Discover COM classes from the registry"""
        if not HAS_WINREG:
            return []

        classes = []
        dll_name_lower = self.dll_name.lower()

        try:
            # Search HKCR\CLSID
            clsid_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID")

            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(clsid_key, i)
                    i += 1

                    try:
                        # Check InprocServer32
                        subkey = winreg.OpenKey(clsid_key, f"{subkey_name}\\InprocServer32")
                        server_path, _ = winreg.QueryValueEx(subkey, "")
                        winreg.CloseKey(subkey)

                        if dll_name_lower in server_path.lower():
                            # Found matching CLSID
                            class_info = {
                                'clsid': subkey_name,
                                'server_path': server_path,
                            }

                            # Try to get class name
                            try:
                                name_key = winreg.OpenKey(clsid_key, subkey_name)
                                class_info['name'], _ = winreg.QueryValueEx(name_key, "")
                                winreg.CloseKey(name_key)
                            except:
                                class_info['name'] = subkey_name

                            classes.append(class_info)

                    except WindowsError:
                        pass

                except WindowsError:
                    break

            winreg.CloseKey(clsid_key)

        except WindowsError:
            pass

        return classes

    def _infer_interfaces(self) -> List[Dict]:
        """Infer interfaces based on exported functions"""
        interfaces = []

        # Check for standard COM interfaces
        if 'DllGetClassObject' in self.exports:
            iid = get_known_iid('IClassFactory')
            interfaces.append({
                'name': 'IClassFactory',
                'iid': str(iid) if iid else None,
                'methods': ['CreateInstance', 'LockServer'],
                'init_method': 'DllGetClassObject',
            })

        # Check for CreateObject style interfaces
        if 'CreateObject' in self.exports:
            interfaces.append({
                'name': 'CreateObject style',
                'iid': None,  # Requires registry or binary scan
                'methods': [],
                'init_method': 'CreateObject',
                'note': 'Use registry lookup or binary scanning to find CLSID/IID',
            })

        return interfaces

    def get_interface_for_method(self, method_name: str) -> Optional[Dict]:
        """
        Get interface information for a specific method

        Args:
            method_name: Method name

        Returns:
            Interface information dictionary, or None
        """
        # Standard COM DLL export functions - direct calls, not interface methods
        standard_exports = {
            'DllGetClassObject', 'DllCanUnloadNow', 'DllRegisterServer',
            'DllUnregisterServer', 'CreateObject', 'GetClassObject',
        }
        if method_name in standard_exports:
            return {
                'interface': None,
                'iid': None,
                'vtable_index': None,
                'init': 'Direct Export',
                'note': 'This is a direct export. Use GetProcAddress.',
            }

        # IUnknown methods
        if method_name in ('QueryInterface', 'AddRef', 'Release'):
            return {
                'interface': 'IUnknown',
                'iid': STANDARD_IIDS.get('IUnknown'),
                'vtable_index': ['QueryInterface', 'AddRef', 'Release'].index(method_name),
                'init': 'CoCreateInstance or CreateObject',
            }

        # IClassFactory methods
        if method_name in ('CreateInstance', 'LockServer'):
            return {
                'interface': 'IClassFactory',
                'iid': STANDARD_IIDS.get('IClassFactory'),
                'vtable_index': 3 + ['CreateInstance', 'LockServer'].index(method_name),
                'init': 'DllGetClassObject',
            }

        # Other exported functions - possibly COM methods if the DLL is COM-compatible
        if method_name in self.exports:
            if self._has_standard_com_exports() or self._has_createobject_exports():
                return {
                    'interface': 'Unknown',
                    'iid': None,  # Requires registry or binary scan
                    'vtable_index': None,
                    'init': 'Requires CLSID/IID',
                    'discovered_guids': [str(g) for g in self.discovered_guids[:10]],
                }

        return None

    def generate_harness_config(self, method_name: str) -> Dict[str, Any]:
        """
        Generate harness configuration for a specific method

        Args:
            method_name: Target method name

        Returns:
            Harness configuration dictionary
        """
        # Execute full discovery first
        discovery_result = self.discover()

        interface_info = self.get_interface_for_method(method_name)

        config = {
            'dll_path': str(self.dll_path),
            'func_name': method_name,
            'is_com_method': discovery_result.get('is_com_dll', False),
            'clsid': None,
            'iid': None,
            'interface_def': None,
            'vtable_index': None,
            'discovered_guids': discovery_result.get('guids', [])[:10],
            'registry_classes': discovery_result.get('classes', []),
        }

        if interface_info:
            if interface_info.get('init') == 'Direct Export':
                config['is_com_method'] = False
                return config

            config['interface_name'] = interface_info.get('interface')

            if interface_info.get('iid') and hasattr(interface_info['iid'], 'to_c_define'):
                config['iid'] = interface_info['iid'].to_c_define()

            if interface_info.get('clsid') and hasattr(interface_info['clsid'], 'to_c_define'):
                config['clsid'] = interface_info['clsid'].to_c_define()

            config['vtable_index'] = interface_info.get('vtable_index')

        # Try to get the first CLSID from registry if none discovered
        if not config['clsid'] and discovery_result.get('classes'):
            first_class = discovery_result['classes'][0]
            clsid_str = first_class.get('clsid', '')
            if clsid_str:
                try:
                    clsid = GUID.from_string(clsid_str)
                    config['clsid'] = clsid.to_c_define()
                    print(f"[*] Using registry CLSID: {clsid_str}")
                except Exception:
                    pass

        # Use scanned GUID as fallback
        if not config['clsid'] and self.discovered_guids:
            best_guid = None
            for guid in self.discovered_guids:
                d1 = guid.data1
                d2 = guid.data2
                d3 = guid.data3
                d4 = guid.data4

                # Exclude small Data1 (likely version/version flags)
                if d1 < 0x10000000:
                    continue

                # Data2/Data3 should both be > 0x1000
                if not (d2 > 0x1000 and d3 > 0x1000):
                    continue

                # Check if Data4 has clear structure (not mostly 0xFF or 0x00)
                if d4.count(0xFF) > 4 or d4.count(0x00) > 6:
                    continue

                best_guid = guid
                break

            if not best_guid:
                best_guid = self.discovered_guids[0]

            config['clsid'] = best_guid.to_c_define()
            print(f"[*] Using scanned CLSID: {best_guid}")

        # Use IUnknown as default IID if CLSID exists but IID doesn't
        if not config['iid'] and config['clsid']:
            config['iid'] = STANDARD_IIDS['IUnknown'].to_c_define()
            print(f"[*] Using default IID: IUnknown")

        return config


def discover_com_info(dll_path: str) -> Dict[str, Any]:
    """
    Convenience function: Discover COM information for a DLL

    Args:
        dll_path: DLL path

    Returns:
        COM discovery result
    """
    discovery = COMDiscovery(dll_path)
    return discovery.discover()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        dll_path = sys.argv[1]
        discovery = COMDiscovery(dll_path)
        info = discovery.discover()

        print(f"\n[*] COM Discovery for: {dll_path}")
        print("=" * 60)
        print(f"Is COM DLL: {info['is_com_dll']}")
        print(f"COM Type: {info['com_type']}")
        print(f"Recommended Init: {info['recommended_init']}")

        print(f"\nExports ({len(info['exports'])}):")
        for exp in info['exports'][:20]:
            print(f"  - {exp}")
        if len(info['exports']) > 20:
            print(f"  ... and {len(info['exports']) - 20} more")

        print(f"\nDiscovered Classes ({len(info['classes'])}):")
        for cls in info['classes']:
            print(f"  - {cls['name']}: {cls['clsid']}")

        print(f"\nDiscovered GUIDs ({len(info['guids'])}):")
        for guid in info['guids'][:10]:
            print(f"  - {guid}")
        if len(info['guids']) > 10:
            print(f"  ... and {len(info['guids']) - 10} more")

        print(f"\nInferred Interfaces ({len(info['interfaces'])}):")
        for iface in info['interfaces']:
            print(f"  - {iface['name']}")
            print(f"    IID: {iface.get('iid', 'N/A')}")
            print(f"    Init: {iface.get('init_method', 'N/A')}")
    else:
        print("Usage: python com_discovery.py <dll_path>")
        print("\nThis tool automatically discovers COM interfaces from DLLs:")
        print("  - Scans exports for COM patterns")
        print("  - Searches registry for registered CLSIDs")
        print("  - Scans binary for embedded GUIDs")
        print("  - Infers interface types from method names")
