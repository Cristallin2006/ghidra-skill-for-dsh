# ghidra-skill-for-dsh

**[简体中文](README.md) | [English](README_EN.md) | 日本語**

[dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)(DeepSeek Harness)向けリバースエンジニアリング agent skill ファミリー:Ghidra 12.x ヘッドレス常駐デーモン(約 0.2 秒/コマンド、Jython/GUI/MCP 不要)+ 8 シナリオの方法論。CTF リバース、crackme、マルウェアトリアージ、脆弱性プレスクリーニング、バイナリ悪用(pwn)、pcap フォレンジック、APK 解析をカバー。

## 実測パフォーマンス

すべての結果は実際の CTF 問題の独立求解(過去の台帳/WP 不使用)であり、オリジナルプログラムによる正負対照検証と session の行単位監査で確認済み。

| 問題 | 题型 | 成績 | 主な証拠 |
|---|---|---|---|
| encode | UPX パッカー + テーブル置換 base64 + RC4 | 40 分で解けず → **16 分で解出** | 同一問題での調校前後比較;高速化の要因はモデルではなく機構:常駐デーモン + 3 つのスクリプトゲート + 関数レベル Oracle + アンパック領域 |
| Reverse-chal | Cython 3.0.10 CPython 拡張;IDEA 変種(mod-65537 乗算)+ SM4 S ボックス + ランダムマスク囮ゲート | **30 分で解出**(この問題で最速;初解は 55 分) | 意味モデリング経路:アルゴリズム族を特定後、ブロック暗号の逆変換を再構成;flag 結論は `--program-accept` 付きで台帳に記録 |
| AegisTrace | pcap 3 フィールドニブル秘匿チャネル + ゼロ参照置換テーブル + カスタムプロトコル完全悪用チェーン | **29 分 / 169 ステップ**でブラインド解出 | 判例ファイルと全回答要素を脱敏移出して再測(対照群 20 分);golden 値は oracle 命中出力で初出、結論はオリジナルプログラムの 8/8 受理応答で終審 |

**同一問題 3 ラウンドリプレイ(Reverse-chal、2026-09-30)** —— 失敗のたびに原因を特定し機械的修正として落地、解出まで:

1. `4ccec36c` 骨格放棄による降参(121 分、flag なし)→ 4 件の修正:骨格使用ゲート / 否定論断の強制記帳 / パス付き降参 stop_check ゲート / `cone_invert.py` 錐形逆推
2. `29bf99c0` 「コンテキスト残り僅か」虚偽降参(19 分、flag なし;実測 1M 窓の使用率 3 割未満)→ さらに 3 件:矛盾分類判詞 / `--diff-symbolize` 入力リテラル自動シンボル化 / 未収束降参ゲート
3. `ddf11a87` **30 分で解出**、2 つの機械ゲートが設計通り発動

**継続的硬化指標**(複数ラウンドの実問題振返り + 第三者敵対的監査、happyVm / DEFCON26 quals 等):

- 擬似コード fatal 誤判ベースライン **6.0% → 2.8%**(末尾呼出し識別)
- ジャンプテーブル / スタックフレーム / 定数の 3 つの高危険「手読み asm」動作を完全スクリプト化
- 台帳は observe/conclude から **observe / conclude / anomaly / hypothesis / plan / stuck の 6 種**に拡張 —— 仮説と列挙予算がチャットだけに存在しなくなった

## 構造(1 基盤 + 8 シナリオ)

| ディレクトリ | 役割 |
|---|---|
| `ghidra-core` | 唯一コードを持つ基盤:engine(ghidra-rpc + dsh パッチ)、`rpc_driver.py` 統一入口、`doctor.py` 環境セルフチェック、3 つのゲート `ledger.py` / `read_views.py` / `crypto_sanity.py`、解析スクリプト層(`decomp_lint` 擬似コード検査 / `jt_resolve` ジャンプテーブル / `frame_map` スタックフレーム / `const_audit` 定数照合 / `emulate_program` プログラム全体エミュレーション / `model_diff` モデル対拍 / `oracle_family` スタブ因子分離等、すべて自己完結で単独呼出可能) |
| `re-triage` | 未知バイナリの第一歩:型/言語/パッカーの 3 信号交差(セクション名 + magic + 構造)、経路決定を出力;foreign-arch ELF ルーティング(Ghidra processor 逆コンパイル優先、objdump は単点照合のみ) |
| `re-unpack` | アンパック + 強制検証:UPX/ASPack/Themida/VMProtect/多層パッカー、PyInstaller ワンストップ(pycdc で Python ≥3.9 をカバー) |
| `ghidra-static` | 静的深堀り:逆コンパイル/xref/注釈/patch/交付;Go/Rust stripped フィンガープリント、CTF パターンライブラリ(fp16 セルフチェックベクタ含む) |
| `vuln-audit` | 脆弱性パターンチェックリスト:メモリ破壊/書式文字列/整数オーバーフロー/コマンドインジェクション等 8 類、到達可能性優先 |
| `re-dynamic` | 動かして見る:関数レベル Oracle(qiling)、スタブ oracle ファミリー(単因子分離)、モデル差分検証、クロスアーキ qemu-user/gdb-multiarch、Frida 時間/乱数ソース hook、Windows GUI メッセージ駆動 |
| `pwn-exploit` | 脆弱性から flag まで:pwn_triage 保護マトリクスハードゲート、checksec 決定木、ROP/fmtstr/ヒープ/FSOP/カーネルレシピライブラリ(370KB、必要時 grep)、pwntools テンプレート 5 点セット、ゲーム/テキストアドベンチャー専章(`references/game-pwn.md`:経済オーバーフロー/数値壁の道標/アイテム編集ヒーププリミティブ);「ローカルで通る ≠ リモートで通る」検証ゲートがリモートエコー記帳を強制 |
| `traffic-analysis` | pcap トリアージ、DNS/ICMP/タイミング秘匿チャネル、USB HID 復元、WPA/TLS 復号;スクリプト全ゼロ依存 + tshark |
| `android-re` | 純 DEX APK:マルチ dex ヒューリスティック、jadx 4 段逆コンパイル、Toast アンカー特定、実機 oracle、v1 再署名 |
| `docs` | 横断ドキュメント:`smoke-tests.md`(新スクリプト/新機能の最小スモーク基準 —— 「書いたが一度も走らない」防止)、`legacy-plugin-pitfalls.md`(旧プラグインの落とし穴アーカイブ)、`cases/`(実問題判例アーカイブ、完全な題解付き、smoke 基準作成時の人的参考専用、skill にリンクバックしない) |

境界ルール:実行コードは core、シナリオ skill は方法論のみ;知識は `references/` の grep 可能なプレーンデータファイルに置き、トリガーポイントポインタでルーティング —— 「知識ベース skill」は作らない。

## インストール

0. **dsh Skill マーケットからインストール**:マーケットソースにリポジトリ URL + git 参照 `v0.9-market` を指定(収録版、実測中の pwn-exploit は未同梱;[Release ページ](https://github.com/Cristallin2006/ghidra-skill-for-dsh/releases/tag/v0.9-market)参照);手動インストールは以下:
1. 9 つのディレクトリを `~/.dsh/skills/` にコピー(pwn-exploit / traffic-analysis / android-re は独立して省略可能;pwn-exploit の exp 実行は WSL ツールチェーンに依存、TOOLCHAIN.md 参照)
2. エンジン venv(Python ≥ 3.11)を作成し editable インストール:
   ```bash
   python3.12 -m venv ~/ghidra-rpc-venv
   ~/ghidra-rpc-venv/Scripts/python.exe -m pip install -e ~/.dsh/skills/ghidra-core/engine/ghidra-rpc
   ```
3. ツール層は [TOOLCHAIN.md](TOOLCHAIN.md) 参照(Tier A/B/C 分級リスト;インストール状態は `doctor.py` の toolchain 節が正)
4. `GHIDRA_INSTALL_DIR`(Ghidra 12.x インストール先)と `JAVA_HOME`(JDK 21+)を設定;任意で `DSH_GHIDRA_WS` でワークスペース指定
5. セルフチェック:`python ~/.dsh/skills/ghidra-core/scripts/doctor.py`(全緑で exit 0)

**Windows 注意**:Ghidra の `ProjectLocator` は `.` で始まるパス要素を拒否するため、`~/.dsh/...` を JVM に直接渡せない —— 基盤は自動的に junction `~/dsh-ghidra-workspace` 経由で動作。

## 使い方(30 秒)

```bash
SK=~/.dsh/skills/ghidra-core/scripts

python "$SK/rpc_driver.py" ensure /path/to/binary          # デーモン起停 + インポート解析(冪等)
python "$SK/rpc_driver.py" triage /path/to/binary          # ワンショットトリアージ
python "$SK/rpc_driver.py" decompile /path/to/binary main  # 逆コンパイル
python "$SK/rpc_driver.py" rename-function /path/to/binary FUN_00401000 check_flag
python "$SK/rpc_driver.py" version-track old.exe new.exe --changed-only
```

先頭引数の `@絶対パス` = 完全 JSON をディスクに出力;書込み操作は即時反映・自動保存。全コマンド一覧は `ghidra-core/SKILL.md`。

## 設計の要点

- **常駐デーモン**:JVM は一度だけ起動、温機後はサブ秒/コマンド;長時間タスク(load / version-track)はバックグラウンド + `@out` 出力
- **機械ゲート、自覚に頼らない**:14 の鉄則の執行体はスクリプト —— `ledger.py`(同領域再訪は `--delta` 必須、結論は書込み即ロック、`resolve` は証拠なしで exit 2 の逆方向ゲート、hypothesis/plan 記帳、`--kind model` 結論は `--anchor` L2 左逆元アンカーの実測必須、hypothesis 三状態ループ confirmed/killed/waived)、`read_views.py`(レンダリングテキスト vs 実バイト照合)、`crypto_sanity.py`(逆変換前後の正当性検査)、違反は一律 exit 2
- **判定性実験優先**:引数の役割/因子関与は呼出規約から推測しない —— `oracle_family.py` のスタブで単因子分離(ベースライン無出力時は因果判詞を自動抑制)、`model_diff.py` モデル対拍が分岐フィンガープリントを出力(幅レベル 16/32 ビット半ブロック規則 + バイトレベル nibble 規則 ⇒ インターフェース誤りでアルゴリズム誤りではない;幅レベル命中では「アルゴリズム誤り疑い」を絶対に記帳しない)
- **検証独立性**:結論は独立ソース必須、なければ ⚠UNVERIFIED 表示 —— Google P0 Naptime の Perfect Verification 原則
- **能力境界**:動的デバッグは Frida/GDB/Qiling/angr に外注;協働プロジェクトは非対応(ghidra-core/SKILL.md §8)

## 規律強制層(dsh-hooks/、オプション)

catalog は skill の description しか注入しない —— SKILL.md 本文と鉄則はコンテキストにない。「AI が skill 規範を守らない」は多くこれに起因する。`dsh-hooks/` は dsh 内蔵の hooks-claude-code ブリッジで主要規律を機械ゲート化:

- **SessionStart/SubagentStart**:セッション作成時に圧縮版規律カード(10 条)を注入(agent が自発的に SKILL.md を読むことに依存しない)
- **PreToolUse(Pwsh|Bash)**:`gate_sample.py` が**台帳なしサンプル**への解析系直読(xxd/strings/objdump…)を exit 2 でブロックしフロー指引を提示(台帳作成後に放行、pcap ヘッダ修復等の合法な開始は免除);`gate_explore.py` が heredoc/cat 落盤式探索を溶断 —— angr 禁止項(フレームスロット/エミュレーション証拠なしにシンボリック実行禁止)、Cython 前置、変種列挙溶断(model_diff.py を直示)、30 分 ≥25 回探索かつ stuck ゼロで強制記帳;`gate_longrun.py` は長時間タスクのディスク出力を強制
- **PreToolUse(Pwsh|Bash|Write|Edit|Read)**:`gate_stuck.py` 停滞自述溶断 —— セッションログ直近 45 分に停滞自述(強い措辞 1 回/弱い措辞 ≥2 メッセージ)があり台帳に stuck がゼロ → exit 2 で記帳強制(判例 b781ff3c:自述 4 回・記帳ゼロ、2 つの半分の事実が 30 分未接続、38 分で exploit ゼロ);episode ごと最大 1 回、活動台帳なしでは不执勤
- **PreToolUse(Write)**:`gate_churn.py` フィッティング溶断 —— ディレクトリ 24 時間 ≥8 個の .py かつ活動台帳 stuck ゼロ → stuck 記帳または z3/emulate への昇格を強制
- **Stop**:`stop_check.py` 收尾照合(既定有効、セッション帰属判定)—— 当セッションの台帳に observe あり後続なし / flag 結論に program_accept 欠落 / open hypothesis 存在 → deny で照合強制

インストール:`dsh-hooks/` を `~/.dsh/hooks/` にコピーし、profile の `cordis.patch.yml` に hooks-claude-code マウント項目を挿入(完全な YAML とトラブルシューティング/ロールバックは `dsh-hooks/README.md`)。変更は **dsh サービス再起動 + 新規セッション**で有効化。

## ライセンスと謝辞

本リポジトリは [MIT](LICENSE) で公開。以下のソースから派生 —— 原作者に感謝:

- [Cellebrite Labs ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc)(MIT、実行エンジン)
- [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)(MIT、方法論)
- [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity) ctf-reverse ナレッジベース
- [Und3rf10w/ai-ghidra-tools](https://github.com/Und3rf10w/ai-ghidra-tools)(ghidra_scripts スクリプト集、現 legacy 凍結層)
- [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)(Apache-2.0、Go/Rust/crypto 識別/JS アンチデバッグ知識片)
- [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)(MIT:ctf-forensics → traffic-analysis レシピ;ctf-pwn → pwn-exploit 知識レシピライブラリ 18 篇 + pwntools テンプレート 5 点)
- [yaklang/hack-skills](https://github.com/yaklang/hack-skills) traffic-analysis-pcap(MIT、決定木骨格)
