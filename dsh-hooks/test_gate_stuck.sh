#!/usr/bin/env bash
# gate_stuck.py 离线自测:假 DSH_HOME + 伪造会话日志/台账
set -u
HOOKS="C:/Users/Lenovo/.kimi-work/ghidra-skill-for-dsh/dsh-hooks"
T=/tmp/gate-stuck-test
PASS=0; FAIL=0

setup() {  # $1=sid
  rm -rf "$T"; mkdir -p "$T/.dsh/sessions/ws/$1" "$T/.dsh/ghidra-workspace/out"
  export DSH_HOME="$T/.dsh"
}
mkledger() { # $1=name  $2=extra entry line(or empty)
  local f="$T/.dsh/ghidra-workspace/out/$1.ledger.jsonl"
  printf '{"type":"observe","ts":"%s","region":"r","note":"n","source":"s"}\n' "$(date '+%F %T')" > "$f"
  [ -n "${2:-}" ] && printf '%s\n' "$2" >> "$f"
}
msg() { # $1=seconds-ago $2=text
  python - "$1" "$2" <<'PY'
import json,sys,time
ago=float(sys.argv[1]); txt=sys.argv[2]
print(json.dumps({"type":"assistant/message","time":int((time.time()-ago)*1000),
 "data":{"message":{"role":"assistant","content":[{"type":"reasoning","text":txt}]}}}))
PY
}
run() { # $1=sid $2=cmd -> echo exit code
  printf '{"session_id":"%s","cwd":"/root/src","tool_name":"bash","tool_input":{"command":"%s"}}' "$1" "$2" \
    | python "$HOOKS/gate_stuck.py" >/dev/null 2>&1; echo $?
}
ck() { # $1=desc $2=got $3=want
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "PASS  $1";
  else FAIL=$((FAIL+1)); echo "FAIL  $1 (got=$2 want=$3)"; fi
}

NOW_S=$(date '+%F %T')

# 1. 强措辞 + 活跃台账无 stuck -> 拦(2)
setup s1; mkledger chal
msg 60 "I'm going around in circles with this hex dump" >> "$T/.dsh/sessions/ws/s1/session.v3.jsonl"
ck "1 强措辞拦截" "$(run s1 'xxd chal.bin | head')" 2

# 2. 拦截后冷却:同 episode 第二次 -> 放(0)
ck "2 冷却放行" "$(run s1 'xxd chal.bin | head')" 0

# 3. 台账有比自述更新的 stuck -> 放(0)
setup s3; mkledger chal "{\"type\":\"stuck\",\"ts\":\"$NOW_S\",\"at\":\"a\",\"tried\":\"t\",\"escalate\":\"e\"}"
msg 300 "I'm going around in circles" >> "$T/.dsh/sessions/ws/s3/session.v3.jsonl"
ck "3 已落账放行" "$(run s3 'xxd chal.bin | head')" 0

# 4. 弱措辞单发 -> 放(0);两发 -> 拦(2)
setup s4; mkledger chal
msg 120 "this approach doesn't work at all" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "4a 弱单发放行" "$(run s4 'cat chal.bin')" 0
msg 90 "ok that path is 行不通 too" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "4b 弱两发拦截" "$(run s4 'cat chal.bin')" 2

# 8. 弱措辞新 episode:把冷却标记改到 10 分钟前(模拟上次拦截已过去),
#    30s/20s 前的新自述晚于标记 -> 再拦(2)
python - <<PY
import json,os
p=os.path.join(os.environ["DSH_HOME"],"ghidra-workspace/out/.stuck-gate.json")
m=json.load(open(p)); m["s4"]=__import__("time").time()-600
json.dump(m,open(p,"w"))
PY
msg 30 "still 行不通, 此路不通" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
msg 20 "and again doesn't work" >> "$T/.dsh/sessions/ws/s4/session.v3.jsonl"
ck "8 新episode再拦" "$(run s4 'cat chal.bin')" 2

# 6. 命令含 ledger.py -> 放(0)
ck "6 ledger豁免" "$(run s4 'python3 ~/.dsh/skills/ghidra-core/scripts/ledger.py stuck chal --at x --tried y --escalate z')" 0

# 5. 无活跃台账(普通开发会话) -> 放(0)
setup s5
msg 60 "the build doesn't work, i'm stuck" >> "$T/.dsh/sessions/ws/s5/session.v3.jsonl"
ck "5 无台账放行" "$(run s5 'npm test')" 0

# 7. 坏 payload -> 放(0)
echo 'not json' | python "$HOOKS/gate_stuck.py" >/dev/null 2>&1
ck "7 坏payload放行" "$?" 0

echo "=== PASS=$PASS FAIL=$FAIL ==="
