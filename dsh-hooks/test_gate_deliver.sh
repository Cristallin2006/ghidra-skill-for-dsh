#!/usr/bin/env bash
# gate_deliver.py 离线自测:假 DSH_HOME + 伪造台账/交付文件
# 2026-10-11 判例 c3964a8b/f7b0ecc2:能力类否定判词交付闸
set -u
HOOKS="${HOOKS:-C:/Users/Lenovo/.kimi-work/ghidra-skill-for-dsh/dsh-hooks}"
T=/tmp/gate-deliver-test
PASS=0; FAIL=0

setup() {  # $1=ledger entry extra line(or empty)
  rm -rf "$T"; mkdir -p "$T/.dsh/ghidra-workspace/out" "$T/work"
  export DSH_HOME="$T/.dsh"
  printf '{"type":"observe","ts":"%s","region":"r","note":"n","source":"s"}\n' \
    "$(date '+%F %T')" > "$T/.dsh/ghidra-workspace/out/chal.ledger.jsonl"
  [ -n "${1:-}" ] && printf '%s\n' "$1" >> "$T/.dsh/ghidra-workspace/out/chal.ledger.jsonl"
}
run() { # $1=tool $2=json-tool-input -> exit code
  printf '{"session_id":"t","cwd":"/root/src","tool_name":"%s","tool_input":%s}' "$1" "$2" \
    | python3 "$HOOKS/gate_deliver.py" >/dev/null 2>&1; echo $?
}
ck() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS  $1";
  else FAIL=$((FAIL+1)); echo "FAIL  $1 (got=$2 want=$3)"; fi }

NEG='{"type":"conclude","kind":"negative","proof":"static-constraint: demo","ts":"2026-10-11 01:00:00"}'

# 1. write REPORT.md 含能力判词,台账无 negative conclude -> 拦(2)
setup
ck "1 write判词拦截" "$(run write '{"file_path":"/x/REPORT.md","content":"stage5 链上有 SHA-256,无法求逆"}')" 2

# 2. write 状态描述(未收敛/尚未解出) -> 放(0)
ck "2 状态描述放行" "$(run write '{"file_path":"/x/REPORT.md","content":"stage5 尚未解出,未收敛,下一步断在消耗点直读"}')" 0

# 3. write 代码文件含判词 -> 放(0,非文档不扫)
ck "3 代码文件放行" "$(run write '{"file_path":"/x/solve.py","content":"# cannot be inverted"}')" 0

# 4. 台账有 negative conclude -> 放(0)
setup "$NEG"
ck "4 有negative-conclude放行" "$(run write '{"file_path":"/x/REPORT.md","content":"无法求逆"}')" 0

# 5. present 读文件内容含判词 -> 拦(2)
setup
echo "the final value cannot be recovered" > "$T/work/REPORT.md"
ck "5 present判词拦截" "$(run present "{\"files\":[{\"path\":\"$T/work/REPORT.md\"}]}")" 2

# 6. present 文件无判词 -> 放(0)
echo "stage5 not solved yet, next step: break at consumption point" > "$T/work/REPORT.md"
ck "6 present状态放行" "$(run present "{\"files\":[{\"path\":\"$T/work/REPORT.md\"}]}")" 0

# 7. bash heredoc 写 answers.txt 含判词 -> 拦(2)
ck "7 bash交付判词拦截" "$(run bash '{"command":"cat > answers.txt <<'"'"'EOF'"'"'\nunsolvable without author input\nEOF"}')" 2

# 8. bash 普通分析命令含判词字样(无交付写入) -> 放(0)
ck "8 bash分析命令放行" "$(run bash '{"command":"grep -c unsolvable trace.log | head"}')" 0

# 9. bash 写 notes.txt(非交付向文件名) -> 放(0)
ck "9 bash非交付文件放行" "$(run bash '{"command":"echo unsolvable > notes.txt"}')" 0

# 10. edit REPORT.md new_string 含判词 -> 拦(2)
ck "10 edit判词拦截" "$(run edit '{"file_path":"/x/REPORT.md","old_string":"a","new_string":"non-invertible map"}')" 2

# 11. 无活跃台账(普通开发会话) -> 放(0)
rm -rf "$T/.dsh/ghidra-workspace/out"; mkdir -p "$T/.dsh/ghidra-workspace/out"
ck "11 无台账放行" "$(run write '{"file_path":"/x/REPORT.md","content":"unsolvable"}')" 0

# 12. 坏 payload -> 放(0)
echo 'not json' | python3 "$HOOKS/gate_deliver.py" >/dev/null 2>&1
ck "12 坏payload放行" "$?" 0

# 13. bare infeasible(爆破成本陈述) -> 放(0)
setup
ck "13 爆破成本陈述放行" "$(run write '{"file_path":"/x/REPORT.md","content":"brute-forcing 2^128 is infeasible, so we invert the Feistel instead"}')" 0

echo "=== PASS=$PASS FAIL=$FAIL ==="
