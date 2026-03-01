import re
import sys

def parse_http_logic(text, overlap_len, session_host, stats):
    """Refinement of the logic used in Heimdall to be tested for accuracy."""
    # 1. Update Host
    hosts = re.finditer(r'Host:\s+(\S+)', text, re.I)
    for h_match in hosts:
        if h_match.end() > overlap_len:
            new_host = h_match.group(1).strip()
            if new_host != session_host:
                # Migration logic
                to_migrate = [k for k in stats.keys() if not k[1].startswith(new_host) and k[1].startswith("/")]
                for m_key in to_migrate:
                    new_key = (m_key[0], f"{new_host}{m_key[1]}")
                    # Add to existing or create new
                    stats[new_key] = stats.get(new_key, 0) + stats.pop(m_key)
                session_host = new_host

    # 2. Match Method + Path
    matches = re.finditer(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\r\n]+)', text, re.I)
    for m in matches:
        # Deduplication: Match must end in the NEW part of the chunk
        if m.end() > overlap_len:
            method = m.group(1).upper()
            path = m.group(2).split('?')[0].split('#')[0]
            path = path.replace("http://", "").replace("https://", "")
            
            full_endpoint = path
            if path.startswith("/") and session_host:
                full_endpoint = f"{session_host}{path}"
            
            key = (method, full_endpoint)
            stats[key] = stats.get(key, 0) + 1
    return session_host

def run_tests():
    print("🚀 Starting Parser Validation Tests (v6 Accurate)...\n")
    
    # Test Split Pattern
    # Chunk 1: "...GE"
    # Chunk 2: "T /index HTTP/1.1"
    stats = {}
    host = ""
    overlap = ""
    
    # Process Chunk 1
    c1 = "DATA...GE"
    host = parse_http_logic(overlap + c1, len(overlap), host, stats)
    overlap = (overlap + c1)[-10:]
    
    # Process Chunk 2
    c2 = "T /index HTTP/1.1\nHost: test.com\n"
    host = parse_http_logic(overlap + c2, len(overlap), host, stats)
    
    expected = {("GET", "test.com/index"): 1}
    if stats == expected:
        print("✅ PASS: Split Pattern (Cross-boundary)")
    else:
        print(f"❌ FAIL: Split Pattern. Got {stats}")
        sys.exit(1)

    print("\n✅ All core parsing logic verified.")

if __name__ == "__main__":
    run_tests()
