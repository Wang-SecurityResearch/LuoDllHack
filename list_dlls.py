#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A tool for listing all DLL files in a directory and analyzing dependency relationships.

Features:
- Recursive or non-recursive search for DLL files
- Multiple output formats
- File information display
- Filtering options
- Performance optimization
- DLL dependency analysis
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List, Iterator, Dict, Set, Optional, Tuple
from collections import defaultdict
import logging

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


def setup_logging(verbose: bool = False):
    """Set up logging"""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def list_dlls(directory: Path, recursive: bool = False) -> Iterator[Path]:
    """
    Get all DLL files in a directory

    Args:
        directory: Directory to search
        recursive: Whether to search recursively

    Yields:
        DLL file paths
    """
    pattern = "**/*.dll" if recursive else "*.dll"
    try:
        for path in directory.glob(pattern):
            if path.is_file():
                yield path.resolve()
    except PermissionError as e:
        logging.warning(f"Permission error, skipping directory: {e}")
    except OSError as e:
        logging.warning(f"System error, skipping: {e}")


def get_file_info(dll_path: Path) -> dict:
    """
    Get detailed information for a DLL file

    Args:
        dll_path: DLL file path

    Returns:
        Dictionary containing file information
    """
    try:
        stat = dll_path.stat()
        return {
            'size': stat.st_size,
            'mtime': stat.st_mtime,
            'is_64bit': _is_64bit_dll(dll_path)
        }
    except OSError:
        return {'size': 0, 'mtime': 0, 'is_64bit': None}


def _is_64bit_dll(dll_path: Path) -> bool:
    """
    Check if a DLL is 64-bit (simplified version, checks file header)

    Args:
        dll_path: DLL file path

    Returns:
        True if 64-bit, False if 32-bit, None if undetermined
    """
    try:
        with open(dll_path, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if len(dos_header) < 64:
                return None

            # Check DOS header signature
            if dos_header[0:2] != b'MZ':
                return None

            # Get PE header position
            pe_offset = int.from_bytes(dos_header[60:64], byteorder='little')
            f.seek(pe_offset)

            # Read PE header
            pe_header = f.read(24)
            if len(pe_header) < 24:
                return None

            # Check PE signature
            if pe_header[0:4] != b'PE\x00\x00':
                return None

            # Check architecture (Machine type at offset 20 of PE header)
            machine_type = int.from_bytes(pe_header[4:6], byteorder='little')
            # 0x8664 = x64, 0x014c = x86
            return machine_type == 0x8664
    except (OSError, ValueError):
        return None


def format_size(size: int) -> str:
    """Format file size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


def filter_dlls(dlls: List[Path], min_size: int = 0, max_size: int = None,
                arch: str = None) -> List[Path]:
    """
    Filter DLL files based on criteria

    Args:
        dlls: List of DLL file paths
        min_size: Minimum file size in bytes
        max_size: Maximum file size in bytes
        arch: Architecture filter ('32', '64', or None)

    Returns:
        Filtered list of DLL file paths
    """
    filtered = []

    for dll in dlls:
        try:
            stat = dll.stat()
            size = stat.st_size

            # Size filtering
            if size < min_size:
                continue
            if max_size and size > max_size:
                continue

            # Architecture filtering
            if arch:
                is_64bit = _is_64bit_dll(dll)
                if arch == '32' and is_64bit:
                    continue
                elif arch == '64' and not is_64bit:
                    continue

            filtered.append(dll)
        except OSError:
            continue  # Skip inaccessible files

    return filtered


# =============================================================================
# DLL Dependency Analysis Functionality
# =============================================================================

# Common system DLL list (used to distinguish between system DLLs and project DLLs)
SYSTEM_DLLS = {
    # Windows Core
    'kernel32.dll', 'kernelbase.dll', 'ntdll.dll', 'user32.dll', 'gdi32.dll',
    'advapi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll', 'comdlg32.dll',
    'comctl32.dll', 'shlwapi.dll', 'version.dll', 'winmm.dll', 'ws2_32.dll',
    'wsock32.dll', 'crypt32.dll', 'secur32.dll', 'rpcrt4.dll', 'setupapi.dll',
    'winspool.drv', 'imm32.dll', 'uxtheme.dll', 'dwmapi.dll', 'dxgi.dll',
    # MSVC Runtime
    'msvcrt.dll', 'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
    'ucrtbase.dll', 'api-ms-win-crt-runtime-l1-1-0.dll',
    'api-ms-win-crt-heap-l1-1-0.dll', 'api-ms-win-crt-string-l1-1-0.dll',
    'api-ms-win-crt-stdio-l1-1-0.dll', 'api-ms-win-crt-math-l1-1-0.dll',
    'api-ms-win-crt-locale-l1-1-0.dll', 'api-ms-win-crt-time-l1-1-0.dll',
    # .NET-related
    'clr.dll', 'clrjit.dll', 'mscorlib.dll', 'mscoree.dll',
}


def get_pe_imports(pe_path: Path) -> Tuple[List[str], List[str]]:
    """
    Get imported DLL list from a PE file

    Args:
        pe_path: PE file path

    Returns:
        (Static imports list, Delay-loaded imports list)
    """
    if not HAS_PEFILE:
        return [], []

    imports = []
    delay_imports = []

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']
        ])

        # Static imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    imports.append(dll_name)
                except Exception:
                    pass

        # Delay-loaded imports
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    delay_imports.append(dll_name)
                except Exception:
                    pass

        pe.close()
    except Exception as e:
        logging.debug(f"Failed to parse PE file {pe_path}: {e}")

    return imports, delay_imports


# LoadLibrary family of APIs
LOADLIBRARY_APIS = {
    'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
    'LdrLoadDll', 'LdrGetDllHandle'
}


def detect_dynamic_imports(pe_path: Path) -> Dict:
    """
    Detect dynamic imports (LoadLibrary calls)

    Args:
        pe_path: PE file path

    Returns:
        {
            'uses_loadlibrary': bool,  # Whether LoadLibrary is used
            'loadlibrary_apis': [...],  # List of LoadLibrary APIs used
            'potential_dlls': [...],    # Potential dynamically loaded DLLs (extracted from strings)
        }
    """
    if not HAS_PEFILE:
        return {'uses_loadlibrary': False, 'loadlibrary_apis': [], 'potential_dlls': []}

    result = {
        'uses_loadlibrary': False,
        'loadlibrary_apis': [],
        'potential_dlls': []
    }

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])

        # Check if LoadLibrary APIs are imported
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    # Only check kernel32.dll, ntdll.dll, and kernelbase.dll
                    if dll_name in ('kernel32.dll', 'ntdll.dll', 'kernelbase.dll'):
                        for imp in entry.imports:
                            if imp.name:
                                api_name = imp.name.decode('utf-8', errors='ignore')
                                if api_name in LOADLIBRARY_APIS:
                                    result['uses_loadlibrary'] = True
                                    result['loadlibrary_apis'].append(api_name)
                except Exception:
                    pass

        # If LoadLibrary is used, scan strings for potential DLL names
        if result['uses_loadlibrary']:
            potential_dlls = set()

            # Scan strings in all sections
            for section in pe.sections:
                try:
                    data = section.get_data()
                    # Extract ASCII strings
                    strings = extract_dll_strings(data)
                    potential_dlls.update(strings)
                except Exception:
                    pass

            # Filter out DLLs that are already in static imports
            static_imports = set()
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                        static_imports.add(dll_name)
                    except Exception:
                        pass

            result['potential_dlls'] = sorted(potential_dlls - static_imports)

        pe.close()
    except Exception as e:
        logging.debug(f"Failed to detect dynamic imports {pe_path}: {e}")

    return result


def extract_dll_strings(data: bytes) -> Set[str]:
    """
    Extract .dll strings from binary data

    Args:
        data: Binary data

    Returns:
        Set of extracted DLL names
    """
    import re
    dlls = set()

    # ASCII strings: xxx.dll
    ascii_pattern = rb'[\x20-\x7e]{3,50}\.dll'
    for match in re.finditer(ascii_pattern, data, re.IGNORECASE):
        try:
            dll_name = match.group().decode('ascii', errors='ignore').lower()
            # Extract last path component
            if '\\' in dll_name:
                dll_name = dll_name.split('\\')[-1]
            if '/' in dll_name:
                dll_name = dll_name.split('/')[-1]
            # Validate reasonable DLL name
            if dll_name.endswith('.dll') and len(dll_name) > 4:
                # Filter out those with invalid characters
                if not any(c in dll_name for c in '<>"|?*'):
                    dlls.add(dll_name)
        except Exception:
            pass

    # Unicode strings (UTF-16LE): xxx.dll
    unicode_pattern = rb'(?:[\x20-\x7e]\x00){3,50}\.d\x00l\x00l\x00'
    for match in re.finditer(unicode_pattern, data, re.IGNORECASE):
        try:
            dll_name = match.group().decode('utf-16-le', errors='ignore').lower()
            if '\\' in dll_name:
                dll_name = dll_name.split('\\')[-1]
            if '/' in dll_name:
                dll_name = dll_name.split('/')[-1]
            if dll_name.endswith('.dll') and len(dll_name) > 4:
                if not any(c in dll_name for c in '<>"|?*'):
                    dlls.add(dll_name)
        except Exception:
            pass

    return dlls


def build_dependency_graph(directory: Path, recursive: bool = True,
                           include_exe: bool = True,
                           detect_dynamic: bool = True) -> Dict[str, Dict]:
    """
    Build dependency graph

    Args:
        directory: Target directory
        recursive: Whether to search recursively
        include_exe: Whether to include EXE files
        detect_dynamic: Whether to detect dynamic imports

    Returns:
        {File Path: {'imports': [...], 'delay_imports': [...], 'dynamic_imports': [...], 'name': ...}}
    """
    if not HAS_PEFILE:
        logging.error("pefile required: pip install pefile")
        return {}

    graph = {}
    pattern = "**/*" if recursive else "*"

    extensions = {'.dll'}
    if include_exe:
        extensions.add('.exe')

    for path in directory.glob(pattern):
        if path.is_file() and path.suffix.lower() in extensions:
            try:
                imports, delay_imports = get_pe_imports(path)

                # Detect dynamic imports
                dynamic_info = {'uses_loadlibrary': False, 'loadlibrary_apis': [], 'potential_dlls': []}
                if detect_dynamic:
                    dynamic_info = detect_dynamic_imports(path)

                if imports or delay_imports or dynamic_info['potential_dlls']:
                    graph[str(path.resolve())] = {
                        'name': path.name.lower(),
                        'imports': imports,
                        'delay_imports': delay_imports,
                        'dynamic_imports': dynamic_info['potential_dlls'],
                        'uses_loadlibrary': dynamic_info['uses_loadlibrary'],
                        'loadlibrary_apis': dynamic_info['loadlibrary_apis'],
                        'path': path
                    }
            except PermissionError:
                logging.debug(f"Permission denied, skipping: {path}")
            except Exception as e:
                logging.debug(f"Failed to process file {path}: {e}")

    return graph


def find_dependents(target_dll: str, graph: Dict[str, Dict]) -> List[Tuple[str, str]]:
    """
    Reverse lookup: find all files that depend on a specified DLL

    Args:
        target_dll: Target DLL name
        graph: Dependency graph

    Returns:
        [(File Path, Import Type), ...] Import Type: 'static', 'delay', or 'dynamic'
    """
    target = target_dll.lower()
    dependents = []

    for file_path, info in graph.items():
        if target in info['imports']:
            dependents.append((file_path, 'static'))
        elif target in info['delay_imports']:
            dependents.append((file_path, 'delay'))
        elif target in info.get('dynamic_imports', []):
            dependents.append((file_path, 'dynamic'))

    return dependents


def find_local_dependencies(directory: Path, graph: Dict[str, Dict]) -> Dict[str, List[Tuple[str, str]]]:
    """
    Identify mutual calls between DLLs within the project (reverse index)

    Args:
        directory: Project directory
        graph: Dependency graph

    Returns:
        {DLL Name: [(Caller File Path, Import Type), ...]}
    """
    # Get filenames of all DLLs in the directory
    local_dlls = set()
    for path in directory.rglob("*.dll"):
        local_dlls.add(path.name.lower())

    # Build reverse index (with import type)
    reverse_deps = defaultdict(list)
    for file_path, info in graph.items():
        # Static imports
        for imp in info['imports']:
            if imp in local_dlls:
                reverse_deps[imp].append((file_path, 'static'))
        # Delay-loaded imports
        for imp in info['delay_imports']:
            if imp in local_dlls:
                reverse_deps[imp].append((file_path, 'delay'))
        # Dynamic imports
        for imp in info.get('dynamic_imports', []):
            if imp in local_dlls:
                reverse_deps[imp].append((file_path, 'dynamic'))

    return dict(reverse_deps)


def is_system_dll(dll_name: str) -> bool:
    """Determine if it is a system DLL"""
    name = dll_name.lower()
    if name in SYSTEM_DLLS:
        return True
    # api-ms-win-* series
    if name.startswith('api-ms-win-'):
        return True
    # ext-ms-* series
    if name.startswith('ext-ms-'):
        return True
    return False


def find_missing_dependencies(graph: Dict[str, Dict], local_dlls: Set[str]) -> Dict[str, List[str]]:
    """
    Detect missing dependencies (referenced but non-existent DLLs)

    Args:
        graph: Dependency graph
        local_dlls: Set of local DLL names

    Returns:
        {File Path: [List of missing DLLs]}
    """
    missing = {}

    for file_path, info in graph.items():
        all_imports = set(info['imports'] + info['delay_imports'])
        file_missing = []

        for dll_name in all_imports:
            # Skip system DLLs
            if is_system_dll(dll_name):
                continue
            # Check if it exists locally
            if dll_name not in local_dlls:
                file_missing.append(dll_name)

        if file_missing:
            missing[file_path] = sorted(file_missing)

    return missing


def find_circular_dependencies(graph: Dict[str, Dict], local_dlls: Set[str]) -> List[List[str]]:
    """
    Detect circular dependencies

    Args:
        graph: Dependency graph
        local_dlls: Set of local DLL names

    Returns:
        List of circular dependency chains, e.g., [[a.dll, b.dll, c.dll, a.dll], ...]
    """
    # Build simplified Name -> Names dependency graph (local DLLs only)
    name_graph = {}
    for file_path, info in graph.items():
        name = info['name']
        if name in local_dlls:
            deps = set()
            for imp in info['imports'] + info['delay_imports']:
                if imp in local_dlls and imp != name:
                    deps.add(imp)
            name_graph[name] = deps

    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node: str, path: List[str]) -> None:
        """DFS to detect cycles"""
        if node in rec_stack:
            # Cycle found, extract it
            cycle_start = path.index(node)
            cycle = path[cycle_start:] + [node]
            # Normalize cycle (start from minimum element to avoid duplicates)
            min_idx = cycle[:-1].index(min(cycle[:-1]))
            normalized = cycle[min_idx:-1] + cycle[:min_idx] + [cycle[min_idx]]
            # Check if already exists
            if normalized not in cycles:
                cycles.append(normalized)
            return

        if node in visited:
            return

        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in name_graph.get(node, []):
            dfs(neighbor, path)

        path.pop()
        rec_stack.remove(node)

    # Start search from each node
    for node in name_graph:
        if node not in visited:
            dfs(node, [])

    return cycles


def find_unused_dlls(graph: Dict[str, Dict], directory: Path, local_dlls: Set[str]) -> List[Tuple[str, Path]]:
    """
    Detect unused DLLs (present in the project but not referenced by any file)
    Only considered unused if not statically, delay-, or dynamically loaded.

    Args:
        graph: Dependency graph
        directory: Project directory
        local_dlls: Set of local DLL names

    Returns:
        [(DLL Name, Full Path), ...]
    """
    # Collect all referenced DLLs (static, delay, dynamic)
    referenced_dlls = set()
    for file_path, info in graph.items():
        # Static imports
        for dll in info['imports']:
            referenced_dlls.add(dll.lower())
        # Delay-loaded imports
        for dll in info['delay_imports']:
            referenced_dlls.add(dll.lower())
        # Dynamic imports
        for dll in info.get('dynamic_imports', []):
            referenced_dlls.add(dll.lower())

    # Identify unreferenced local DLLs
    unused = []
    for path in directory.rglob("*.dll"):
        dll_name = path.name.lower()
        if dll_name in local_dlls and dll_name not in referenced_dlls:
            unused.append((dll_name, path))

    return sorted(unused, key=lambda x: x[0])


def analyze_dependency_issues(graph: Dict[str, Dict], directory: Path) -> Dict:
    """
    Analyze dependency issues (missing dependencies, circular dependencies, and unused DLLs)

    Args:
        graph: Dependency graph
        directory: Project directory

    Returns:
        {'missing': {...}, 'circular': [...], 'unused': [...]}
    """
    # Get local DLL set
    local_dlls = set()
    for path in directory.rglob("*.dll"):
        local_dlls.add(path.name.lower())

    missing = find_missing_dependencies(graph, local_dlls)
    circular = find_circular_dependencies(graph, local_dlls)
    unused = find_unused_dlls(graph, directory, local_dlls)

    return {
        'missing': missing,
        'circular': circular,
        'unused': unused,
        'local_dlls': local_dlls
    }


def print_dependency_tree(file_path: str, info: Dict, graph: Dict[str, Dict],
                           local_dlls: Set[str], show_system: bool = False,
                           indent: int = 0, visited: Set[str] = None):
    """
    Print dependency tree

    Args:
        file_path: File path
        info: File information
        graph: Dependency graph
        local_dlls: Set of local DLL names
        show_system: Whether to show system DLLs
        indent: Indentation level
        visited: Set of visited nodes (for cycle prevention)
    """
    if visited is None:
        visited = set()

    prefix = "  " * indent

    # Prevent infinite recursion from circular dependencies
    if file_path in visited:
        return
    visited.add(file_path)

    # Collect all imports
    all_imports = info['imports'] + info['delay_imports']
    delay_set = set(info['delay_imports'])
    dynamic_set = set(info.get('dynamic_imports', []))

    # Merge all imports (deduplicated)
    all_dlls = set(all_imports) | dynamic_set

    for dll_name in sorted(all_dlls):
        is_local = dll_name in local_dlls
        is_sys = is_system_dll(dll_name)
        is_delay = dll_name in delay_set
        is_dynamic = dll_name in dynamic_set

        if not show_system and is_sys:
            continue

        # Build labels
        labels = []
        if is_local:
            labels.append("Local")
        elif is_sys:
            labels.append("System")
        else:
            labels.append("External")

        if is_dynamic:
            labels.append("Dynamic Loaded")
        elif is_delay:
            labels.append("Delay Loaded")

        label_str = f" ({', '.join(labels)})"

        # Tree connector symbols
        connector = "├── " if indent > 0 else ""
        # Special marker for dynamic imports
        marker = "~" if is_dynamic else ""
        print(f"{prefix}{connector}{marker}{dll_name}{label_str}")

        # Recurse if local DLL (limit depth)
        if is_local and indent < 3:
            # Find full path for this DLL
            for fp, fp_info in graph.items():
                if fp_info['name'] == dll_name:
                    print_dependency_tree(fp, fp_info, graph, local_dlls,
                                         show_system, indent + 1, visited.copy())
                    break


def print_deps_summary(graph: Dict[str, Dict], directory: Path,
                        show_system: bool = False, format_type: str = "tree",
                        target_dll: str = None, target_file: str = None):
    """
    Print dependency relationship summary

    Args:
        graph: Dependency graph
        directory: Project directory
        show_system: Whether to show system DLLs
        format_type: Output format (tree, json, dot, list)
        target_dll: Look up callers for target_dll
        target_file: Look up dependencies for target_file
    """
    # Get local DLL set
    local_dlls = set()
    for path in directory.rglob("*.dll"):
        local_dlls.add(path.name.lower())

    # Mode 1: Query who depends on specified DLL
    if target_dll:
        dependents = find_dependents(target_dll, graph)
        if not dependents:
            print(f"No files found depending on {target_dll}")
            return

        print(f"\n=== Files depending on {target_dll} ===\n")
        for file_path, import_type in sorted(dependents):
            type_labels = {
                'static': '',
                'delay': '[Delay Loaded]',
                'dynamic': '[Dynamic Loaded]'
            }
            type_label = type_labels.get(import_type, '')
            print(f"  {Path(file_path).name} {type_label}")
            print(f"    Path: {file_path}")
        print(f"\nTotal: {len(dependents)} file(s) depend on {target_dll}")
        return

    # Mode 2: Query dependencies for specified file
    if target_file:
        target_path = Path(target_file)
        if not target_path.is_absolute():
            target_path = directory / target_file

        target_key = None
        for fp in graph:
            if Path(fp).name.lower() == target_path.name.lower() or fp == str(target_path.resolve()):
                target_key = fp
                break

        if not target_key:
            print(f"File not found: {target_file}")
            return

        info = graph[target_key]
        print(f"\n=== Dependencies of {Path(target_key).name} ===\n")
        print_dependency_tree(target_key, info, graph, local_dlls, show_system)

        total = len(set(info['imports'] + info['delay_imports']))
        local_count = len([d for d in info['imports'] + info['delay_imports'] if d in local_dlls])
        print(f"\nTotal dependencies: {total} DLL(s) (Local: {local_count})")
        return

    # Mode 3: Display all dependency relationships
    if format_type == "json":
        import json
        # Analyze dependency issues
        issues = analyze_dependency_issues(graph, directory)

        # Count dynamic imports
        files_with_dynamic = sum(1 for info in graph.values() if info.get('dynamic_imports'))
        total_dynamic = sum(len(info.get('dynamic_imports', [])) for info in graph.values())

        output = {
            'files': {},
            'issues': {
                'missing_dependencies': issues['missing'],
                'circular_dependencies': issues['circular'],
                'unused_dlls': [{'name': name, 'path': str(path)} for name, path in issues['unused']]
            },
            'summary': {
                'total_files': len(graph),
                'local_dlls': len(issues['local_dlls']),
                'missing_count': sum(len(v) for v in issues['missing'].values()),
                'circular_count': len(issues['circular']),
                'unused_count': len(issues['unused']),
                'dynamic_import_files': files_with_dynamic,
                'dynamic_import_dlls': total_dynamic
            }
        }
        for file_path, info in graph.items():
            output['files'][file_path] = {
                'name': info['name'],
                'imports': info['imports'],
                'delay_imports': info['delay_imports'],
                'dynamic_imports': info.get('dynamic_imports', []),
                'uses_loadlibrary': info.get('uses_loadlibrary', False),
                'loadlibrary_apis': info.get('loadlibrary_apis', [])
            }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    if format_type == "dot":
        print("digraph DependencyGraph {")
        print("  rankdir=LR;")
        print("  node [shape=box];")

        # Define node styles
        for file_path, info in graph.items():
            name = info['name']
            if name.endswith('.exe'):
                print(f'  "{name}" [style=filled, fillcolor=lightblue];')
            elif name in local_dlls:
                print(f'  "{name}" [style=filled, fillcolor=lightgreen];')

        # Define edges
        for file_path, info in graph.items():
            src = info['name']
            for imp in info['imports']:
                if imp in local_dlls or show_system:
                    print(f'  "{src}" -> "{imp}";')
            for imp in info['delay_imports']:
                if imp in local_dlls or show_system:
                    print(f'  "{src}" -> "{imp}" [style=dashed];')

        print("}")
        return

    # Default: tree display
    print("\n" + "=" * 60)
    print("DLL Dependency Relationship Analysis")
    print("=" * 60)

    # Analyze dependency issues
    issues = analyze_dependency_issues(graph, directory)
    missing_deps = issues['missing']
    circular_deps = issues['circular']
    unused_dlls = issues['unused']

    # Display warnings
    has_warnings = False

    if circular_deps:
        has_warnings = True
        print("\n" + "!" * 60)
        print("[WARNING] Circular Dependencies Detected")
        print("!" * 60)
        for i, cycle in enumerate(circular_deps, 1):
            cycle_str = " → ".join(cycle)
            print(f"  {i}. {cycle_str}")

    if missing_deps:
        has_warnings = True
        print("\n" + "!" * 60)
        print("[WARNING] Missing Dependencies Detected")
        print("!" * 60)
        for file_path, missing_list in sorted(missing_deps.items()):
            print(f"\n  {Path(file_path).name}:")
            for dll in missing_list:
                print(f"    ✗ {dll} (Not Found)")

    if has_warnings:
        print("\n" + "!" * 60)

    # Display EXE files first
    exe_files = [(fp, info) for fp, info in graph.items() if info['name'].endswith('.exe')]
    dll_files = [(fp, info) for fp, info in graph.items() if info['name'].endswith('.dll')]

    if exe_files:
        print("\n[Executable Files]")
        for file_path, info in sorted(exe_files, key=lambda x: x[1]['name']):
            print(f"\n{info['name']}")
            print_dependency_tree(file_path, info, graph, local_dlls, show_system, indent=1)

    # Display local DLL dependencies
    local_dll_files = [(fp, info) for fp, info in dll_files if info['name'] in local_dlls]
    if local_dll_files:
        print("\n[Local DLLs]")
        for file_path, info in sorted(local_dll_files, key=lambda x: x[1]['name']):
            # Only show DLLs with local dependencies
            local_imports = [d for d in info['imports'] + info['delay_imports'] if d in local_dlls]
            if local_imports or show_system:
                print(f"\n{info['name']}")
                print_dependency_tree(file_path, info, graph, local_dlls, show_system, indent=1)

    # Display reverse dependency summary
    reverse_deps = find_local_dependencies(directory, graph)
    if reverse_deps:
        print("\n" + "-" * 40)
        print("[Invocation Statistics] (Local DLLs)")
        print("-" * 40)
        for dll_name, callers in sorted(reverse_deps.items(), key=lambda x: -len(x[1])):
            print(f"\n{dll_name} (Invoked by {len(callers)} file(s))")
            for caller_path, import_type in sorted(callers, key=lambda x: x[0]):
                type_marker = ""
                if import_type == 'dynamic':
                    type_marker = " [Dynamic]"
                elif import_type == 'delay':
                    type_marker = " [Delay]"
                print(f"  ← {Path(caller_path).name}{type_marker}")

    # Count dynamic imports
    files_with_dynamic = [(fp, info) for fp, info in graph.items() if info.get('dynamic_imports')]
    total_dynamic_dlls = sum(len(info.get('dynamic_imports', [])) for info in graph.values())

    # Display unused DLLs at the end
    if unused_dlls:
        print("\n" + "-" * 40)
        print("[Unused DLLs] (Possible redundant files)")
        print("-" * 40)
        for dll_name, dll_path in unused_dlls:
            print(f"  ○ {dll_name}")
            print(f"    Path: {dll_path}")

    # Summary information
    print("\n" + "=" * 60)
    print(f"Total files analyzed: {len(graph)}, Local DLLs: {len(local_dlls)}")
    if circular_deps:
        print(f"[!] Circular dependencies: {len(circular_deps)}")
    if missing_deps:
        total_missing = sum(len(v) for v in missing_deps.values())
        print(f"[!] Missing dependencies: {total_missing} (Involving {len(missing_deps)} file(s))")
    if files_with_dynamic:
        print(f"[~] Dynamically loaded: {total_dynamic_dlls} DLL(s) (Involving {len(files_with_dynamic)} file(s))")
    if unused_dlls:
        print(f"[○] Unused: {len(unused_dlls)} DLL(s)")
    print("=" * 60)


def print_summary(dlls: List[Path], show_details: bool = False,
                  show_arch: bool = False, format_type: str = "plain"):
    """
    Print DLL list or summary

    Args:
        dlls: List of DLL file paths
        show_details: Whether to show detailed information
        show_arch: Whether to show architecture info
        format_type: Output format ('plain', 'detailed', 'json', 'csv')
    """
    if format_type == "count":
        print(len(dlls))
        return

    if format_type == "json":
        import json
        output = []
        for dll in dlls:
            info = {'path': str(dll)}
            if show_details:
                file_info = get_file_info(dll)
                info.update({
                    'size': file_info['size'],
                    'size_formatted': format_size(file_info['size']),
                    'is_64bit': file_info['is_64bit']
                })
            output.append(info)
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    if format_type == "csv":
        print("Path,Size,Size_Formatted,Is_64bit")
        for dll in dlls:
            file_info = get_file_info(dll)
            size_formatted = format_size(file_info['size'])
            is_64bit = file_info['is_64bit']
            print(f'"{dll}",{file_info["size"]},{size_formatted},{is_64bit}')
        return

    # Plain output
    for dll in dlls:
        if show_details or show_arch:
            file_info = get_file_info(dll)
            size_str = format_size(file_info['size'])
            arch_str = ""
            if show_arch:
                arch = file_info['is_64bit']
                if arch is True:
                    arch_str = " [64-bit]"
                elif arch is False:
                    arch_str = " [32-bit]"
                else:
                    arch_str = " [Unknown]"
            print(f"{dll} ({size_str}){arch_str}")
        else:
            print(dll)

    if format_type != "quiet":
        print(f"\nTotal: {len(dlls)} DLL(s)", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="List all DLL files in a directory and analyze dependency relationships.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/directory                    # List DLLs in directory
  %(prog)s /path/to/directory --recursive        # Recursive search
  %(prog)s /path/to/directory --count            # Show count only
  %(prog)s /path/to/directory --format json      # JSON output
  %(prog)s /path/to/directory --arch 64          # Show 64-bit DLLs only
  %(prog)s /path/to/directory --min-size 100KB   # Filter by file size

Dependency analysis examples:
  %(prog)s /path/to/project --deps               # Analyze intra-project DLL dependencies
  %(prog)s /path/to/project --deps --show-system # Include system DLLs
  %(prog)s /path/to/project --who-uses mylib.dll # Check who uses mylib.dll
  %(prog)s /path/to/project --imports app.exe    # Check app.exe dependencies
  %(prog)s /path/to/project --deps --format dot  # Export Graphviz DOT format
        """
    )

    parser.add_argument("directory", type=Path, help="Target directory")
    parser.add_argument("-r", "--recursive", action="store_true",
                       help="Search subdirectories recursively")
    parser.add_argument("-c", "--count", action="store_true",
                       help="Show count only")
    parser.add_argument("-d", "--details", action="store_true",
                       help="Show detailed info")
    parser.add_argument("-a", "--arch", choices=['32', '64'],
                       help="Filter architecture (32 or 64 bit)")
    parser.add_argument("--min-size", type=str, default="0",
                       help="Minimum file size (e.g., 100KB, 1MB) - Default: 0")
    parser.add_argument("--max-size", type=str,
                       help="Maximum file size (e.g., 10MB, 100MB)")
    parser.add_argument("--format", choices=['plain', 'detailed', 'json', 'csv', 'quiet', 'dot'],
                       default='plain', help="Output format (Default: plain)")
    parser.add_argument("--show-arch", action="store_true",
                       help="Show architecture information")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Show verbose logs")

    # Dependency analysis arguments
    deps_group = parser.add_argument_group('Dependency Analysis')
    deps_group.add_argument("--deps", action="store_true",
                           help="Analyze DLL dependency relationships")
    deps_group.add_argument("--who-uses", type=str, metavar="DLL",
                           help="Check which files call the specified DLL")
    deps_group.add_argument("--imports", type=str, metavar="FILE",
                           help="Check which DLLs the specified file depends on")
    deps_group.add_argument("--show-system", action="store_true",
                           help="Show system DLL dependencies (Hidden by default)")
    deps_group.add_argument("--no-exe", action="store_true",
                           help="Exclude EXE files during dependency analysis")

    args = parser.parse_args()

    setup_logging(args.verbose)

    if not args.directory.exists():
        print(f"Error: Directory does not exist: {args.directory}", file=sys.stderr)
        sys.exit(1)

    if not args.directory.is_dir():
        print(f"Error: Not a directory: {args.directory}", file=sys.stderr)
        sys.exit(1)

    # Parse size arguments
    def parse_size(size_str):
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(float(size_str[:-2]) * 1024)
        elif size_str.endswith('MB'):
            return int(float(size_str[:-2]) * 1024 * 1024)
        elif size_str.endswith('GB'):
            return int(float(size_str[:-2]) * 1024 * 1024 * 1024)
        elif size_str.endswith('B'):
            return int(float(size_str[:-1]))
        else:
            # Assume pure number (bytes)
            return int(size_str)

    min_size = parse_size(args.min_size)
    max_size = parse_size(args.max_size) if args.max_size else None

    # Timing
    start_time = time.time()

    try:
        # Dependency analysis mode
        if args.deps or args.who_uses or args.imports:
            if not HAS_PEFILE:
                print("Error: Dependency analysis requires pefile: pip install pefile", file=sys.stderr)
                sys.exit(1)

            # Build dependency graph
            graph = build_dependency_graph(
                args.directory,
                recursive=args.recursive or True,  # Default to recursive for dependency analysis
                include_exe=not args.no_exe
            )

            if not graph:
                print("No PE files found for analysis", file=sys.stderr)
                sys.exit(1)

            # Print dependency relationships
            print_deps_summary(
                graph,
                args.directory,
                show_system=args.show_system,
                format_type=args.format if args.format in ('json', 'dot') else 'tree',
                target_dll=args.who_uses,
                target_file=args.imports
            )

            # Show performance info
            if args.verbose:
                elapsed = time.time() - start_time
                logging.info(f"Dependency analysis completed in: {elapsed:.2f} seconds")

            return

        # Normal mode: list DLL files
        dlls = list(list_dlls(args.directory, args.recursive))

        # Filtering
        if min_size > 0 or max_size or args.arch:
            dlls = filter_dlls(dlls, min_size, max_size, args.arch)

        # Output
        if args.count:
            print(len(dlls))
        else:
            print_summary(dlls, args.details or args.format == 'detailed',
                         args.show_arch, args.format if not args.count else 'count')

        # Show performance info
        if args.verbose:
            elapsed = time.time() - start_time
            logging.info(f"Process completed in: {elapsed:.2f} seconds")

    except KeyboardInterrupt:
        print("\nOperation interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
