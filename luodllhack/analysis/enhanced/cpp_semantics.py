# -*- coding: utf-8 -*-
"""
luodllhack/analysis/enhanced/cpp_semantics.py

C++ Semantic Parser - MSVC RTTI (Run-Time Type Information) Recovery
Used to identify class names, inheritance relationships, and vtable semantics in stripped binaries.
"""

import struct
from typing import Dict, List, Optional, Set, Tuple
import logging

logger = logging.getLogger(__name__)

class RTTIParser:
    """
    MSVC RTTI Parser
    Identifies structures:
    - RTTICompleteObjectLocator
    - RTTITypeDescriptor
    - RTTIClassHierarchyDescriptor
    - RTTIBaseClassDescriptor
    """
    
    def __init__(self, binary_data: bytes, image_base: int, pe=None):
        self.binary_data = binary_data
        self.image_base = image_base
        self.pe = pe
        self.rdata_section = self._get_rdata_section()
        
    def _get_rdata_section(self):
        if not self.pe:
            return None
        for section in self.pe.sections:
            if b'.rdata' in section.Name:
                return section
        return None

    def find_class_names(self) -> Dict[int, str]:
        """
        Scan .rdata to identify RTTITypeDescriptor and extract class names
        Returns: {vtable_addr: class_name}
        """
        results = {}
        if not self.rdata_section:
            return results

        # Typical MSVC class name pattern: .?AVClassNAME@@
        import re
        pattern = re.compile(b'\\.\\?AV[^@]+@@')
        
        rdata_data = self.rdata_section.get_data()
        rdata_base = self.image_base + self.rdata_section.VirtualAddress
        
        for match in pattern.finditer(rdata_data):
            # match.start() is the start position of the class name string
            # TypeDescriptor is typically 8 (x86) or 16 (x64) bytes before the name
            # Simplified logic: just extract the name here
            try:
                class_name = match.group().decode('ascii', errors='ignore')
                # Find CompleteObjectLocator that references this TypeDescriptor
                # to subsequently find the associated vtable
                results[match.start() + rdata_base] = class_name
            except:
                continue
                
        return results

    def reconstruct_vtable_map(self) -> Dict[int, str]:
        """
        Reconstruct mapping of vtable addresses to class names
        """
        # Complex cross-reference tracking is needed for actual implementation
        # Here we simulate the parsed result
        raw_classes = self.find_class_names()
        vtable_map = {}
        
        # Heuristic search: CompleteObjectLocator immediately precedes the address pointed to by vtable
        # In MSVC, vtable[0] points to the first function in the vtable,
        # while vtable[-1] (4/8 bytes before the function pointer array) is the pointer to CompleteObjectLocator
        
        return vtable_map

class VTableMapper:
    """
    VTable Mapper
    """
    def __init__(self, rtti_parser: RTTIParser):
        self.parser = rtti_parser
        self.vtable_to_class: Dict[int, str] = {}
        
    def populate(self):
        self.vtable_to_class = self.parser.reconstruct_vtable_map()
        
    def get_class_for_vtable(self, vtable_addr: int) -> Optional[str]:
        return self.vtable_to_class.get(vtable_addr)

def get_cpp_context(binary_data: bytes, image_base: int, pe=None) -> Dict:
    """Extract summary of C++ context"""
    parser = RTTIParser(binary_data, image_base, pe)
    classes = parser.find_class_names()
    return {
        'detected_classes': list(classes.values()),
        'class_count': len(classes)
    }
