import sys, psutil, time, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
def get_full_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmdline = f.read().replace("\0", " ").strip()
            return cmdline if cmdline else "-"
    except:
        return "-"

found = None
for p in psutil.process_iter(['pid', 'name']):
    if p.info['name'] == 'nc':
        found = p.info['pid']
        break
if not found:
    print("nc not found")
    sys.exit(0)

curr_p = str(found)
print("Start PID:", curr_p, get_full_cmdline(curr_p))
pids_to_strike = set([curr_p])
scripts_found = set()
for level in range(12):
    if not curr_p or curr_p in ("0", "1"): break
    try:
        with open(f"/proc/{curr_p}/stat", "r") as f:
            content = f.read()
        match = re.search(r"(\d+) \((.*)\) [A-Zrt] (\d+)", content)
        if not match: break
        name = match.group(2)
        ppid = match.group(3)
        cmdline = get_full_cmdline(curr_p)
        print(f"Level {level}: PID {curr_p}, PPID {ppid}, Name {name}, Cmd {cmdline}")
        is_shell = name in ("bash", "sh")
        has_script = any(ext in cmdline for ext in (".sh", ".py", ".pl", ".js", ".php"))
        
        if is_shell and not has_script:
            print("Protected interactive shell!")
            break
            
        if has_script:
            print("Found script!")
            scripts_found.add("DUMMY")
            
        curr_p = ppid
    except Exception as e:
        print("Error:", e)
        break
