#!/usr/bin/env bash
# gate_stuck.py 离线自测:假 DSH_HOME + 伪造会话日志/台账
# v2(2026-10-11):豁免收紧(只读子命令不再豁免真实工作)、写条目清 episode、复拦阻尼
set -u
HOOKS="${HOOKS:-C:/Users/Lenovo/.kimi-work/ghidra-skill-for-dsh/dsh-hooks}"
PY="$(command -v python || command -v python3)"
T=/tmp/gate-stuck-test
PASS=0; FAIL=0

setup() {  # $1=sid
  rm -rf "$T"; mkdir -p "$T/.dsh/sessions/ws/$1" "$T/.dsh/ghidra-workspace/out"
  export DSH_HOME="$T/.dsh"
}
mkledger() { # $1=name  $2=extra entry line(or empty)
  # 默认 observe 落在 1h 前:比测试里的自述旧,不触发「写清 episode」
  local f="$T/.dsh/ghidra-workspace/out/$1.ledger.jsonl"
  printf '{"type":"observe","ts":"%s","region":"r","note":"n","source":"s"}\n' \
    "$(date -d '1 hour ago' '+%F %T' 2>/dev/null || date '+%F %T')" > "$f"
  [ -n "${2:-}" ] && printf '%s\n' "$2" >> "$f"
}
msg() { # $1=seconds-ago $2=text
  "$PY" - "$1" "$2" <<'PY'
import json,sys,time
ago=float(sys.argv[1]); txt=sys.argv[2]
print(json.dumps({"type":"assistant/message","time":int((time.time()-ago)*1000),
 "data":{"message":{"role":"assistant","content":[{"type":"reasoning","text":txt}]}}}))
PY
}
run() { # $1=sid $2=cmd -> echo exit code
  printf '{"session_id":"%s","cwd":"/root/src","tool_name":"bash","tool_input":{"command":"%s"}}' "$1" "$2" \
    | "$PY" "$HOOKS/gate_stuck.py" >/dev/null 2>&1; echo $?
}
ck() { # $1=desc $2=got $3=want
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS  $1";
  else FAIL=$((FAIL+1)); echo "FAIL  $1 (got=$2 want=$3)"; fi
}

NOW_S=$(date '+%F %T')

# 1. 强措辞 + 活跃台账无新写 -> 拦(2)
setup s1; mkledger chal
msg 60 "I'm going around in circles with this hex dump" >> "$T/.dsh/sessions/ws/s1/session.v3.jsonl"
ck "1 强措辞拦截" "$(run s1 'xxd chal.bin | head')" 2

# 2. 拦截后冷却:同 episode 第二次 -> 放(0)
ck "2 冷却放行" "$(run s1 'xxd chal.bin | head')" 0

# 3. 台账有比自述更新的写条目(stuck) -> 放(0)
setup s3; mkledger chal "{\"type\":\"stuck\",\"ts\":\"$NOW_S\",\"at\":\"a\",\"tried\":\"t\",\"escalate\":\"e\"}"
msg 300 "I'm going around in circles" >> "$T/.dsh/sessions/ws/s3/session.v3.jsonl"
ck "3 已落账放行" "$(run s3 'xxd chal.bin | head')" 0

# 3b. v2:自述后有新 observe(误检说明路径真实生效) -> 放(0)
setup s3b; mkledger chal
msg 120 "this doesn't work, maybe doesn't work at all" >> "$T/.dsh/sessions/ws/s3b/session.v3.jsonl"
printf '{"type":"observe","ts":"%s","region":"r","note":"说明现状","source":"s"}\n' "$NOW_S" \
  >> "$T/.dsh/ghidra-workspace/out/chal.ledger.jsonl"
ck "3b observe清episode" "$(run s3b 'xxd chal.bin | head')" 0

# 4. 弱措辞单发 -> 放(0);两发 -> 拦(2)
setup s4; mkledger chal
msg 120 "this approach doesn't work at all" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "4a 弱单发放行" "$(run s4 'cat chal.bin')" 0
msg 90 "ok that path is 行不通 too" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "4b 弱两发拦截" "$(run s4 'cat chal.bin')" 2

# 8. v2 阻尼:上次拦截 10min 前(窗口内),仅弱措辞复诉 -> 放(0)
"$PY" - <<PY
import json,os
p=os.path.join(os.environ["DSH_HOME"],"ghidra-workspace/out/.stuck-gate.json")
m=json.load(open(p)); m["s4"]=__import__("time").time()-600
json.dump(m,open(p,"w"))
PY
msg 30 "still 行不通, 此路不通" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
msg 20 "and again doesn't work" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "8a 阻尼窗口内弱复诉放行" "$(run s4 'cat chal.bin')" 0

# 8b. 阻尼不护强措辞:窗口内新强自述 -> 拦(2)
msg 10 "ok now i'm stuck, going in circles" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "8b 窗口内强措辞复拦" "$(run s4 'cat chal.bin')" 2

# 8c. 阻尼窗外(20min)的弱措辞新 episode -> 拦(2)
setup s8c; mkledger chal
"$PY" - <<PY
import json,os
p=os.path.join(os.environ["DSH_HOME"],"ghidra-workspace/out/.stuck-gate.json")
json.dump({"s8c":__import__("time").time()-1200},open(p,"w"))
PY
msg 30 "行不通 again" >> "$T/.dsh/sessions/ws/s8c/session.v3.jsonl"
msg 20 "and doesn't work too" >> "$T/.dsh/sessions/ws/s8c/session.v3.jsonl"
ck "8c 窗外弱复诉拦截" "$(run s8c 'cat chal.bin')" 2

# 6. 台账写操作命令 -> 放(0)
ck "6 写操作豁免" "$(run s8c 'python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck chal --at x --tried y --escalate z')" 0

# 9. v2 判例 f7b0ecc2:query 前缀贴真实工作 -> 拦(2)
setup s9; mkledger chal
msg 60 "i'm stuck on this stage" >> "$T/.dsh/sessions/ws/s9/session.v3.jsonl"
ck "9 query前缀不豁免" "$(run s9 'L=$HOME/.dsh/skills/ghidra-core/scripts/ledger.py; python3 $L query chal >/dev/null 2>&1; xxd chal.bin | head')" 2

# 10. 纯 query 盘点(出口②不堵死) -> 放(0)
#     上一用例已拦过一次,先清标记模拟同 episode 未被拦的场景
setup s10; mkledger chal
msg 60 "i'm stuck on this stage" >> "$T/.dsh/sessions/ws/s10/session.v3.jsonl"
ck "10 纯query放行" "$(run s10 'python3 $HOME/.dsh/skills/ghidra-core/scripts/ledger.py query chal')" 0
ck "10b 纯query+管道查看放行" "$(run s10 'L=$HOME/.dsh/skills/ghidra-core/scripts/ledger.py && python3 $L query chal 2>&1 | head -60')" 0

# 5. 无活跃台账(普通开发会话) -> 放(0)
setup s5
msg 60 "the build doesn't work, i'm stuck" >> "$T/.dsh/sessions/ws/s5/session.v3.jsonl"
ck "5 无台账放行" "$(run s5 'npm test')" 0

# 7. 坏 payload -> 放(0)
echo 'not json' | "$PY" "$HOOKS/gate_stuck.py" >/dev/null 2>&1
ck "7 坏payload放行" "$?" 0

echo "=== PASS=$PASS FAIL=$FAIL ==="
