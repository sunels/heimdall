
import os
import sys
# Add current dir to path to import heimdall
sys.path.append(os.getcwd())
from heimdall import resolve_service_knowledge, get_local_package_info, _find_binary_path

prog = "master"
port = 25
pid = "3263" # From user's screenshot

print(f"Testing for {prog} (pid {pid})...")
bin_path = _find_binary_path(prog, pid=pid)
print(f"Binary path: {bin_path}")

info = get_local_package_info(prog, pid=pid)
print(f"Local package info: {info}")

full_info, is_unknown = resolve_service_knowledge(prog, port, pid=pid)
print(f"Full resolved info: {full_info}")
print(f"Is unknown: {is_unknown}")
