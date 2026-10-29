#!/bin/sh
# vim: set sw=2 ts=2 et:
set -eu

# -------------------------------------------------------------------------
# 跨 awk 实现差分测试：update-chnroute.sh 的 IPv6 校验程序
#
# 由来：Ubuntu 22.04 自带的 awk 是 mawk，其正则引擎对嵌套区间量词 {n,m} 的
# 处理与 gawk / OpenWrt busybox awk 不一致——同一段「9 分支大 ERE」校验程序
# 在 mawk 上会把每条正常地址全判非法（整个 IPv6 族更新失败并 exit 1），在
# 别的实现上却正常。校验程序因此改为不用正则（只用 index / substr / length），
# 本测试负责把「各实现行为一致」从口头保证变成可执行断言：
#
#   1. 从 update-chnroute.sh 里按 AWK_PARITY_BEGIN/END 注释标记抽出校验程序，
#      保证测的就是生产代码本身，而不是另外维护的副本；
#   2. 用本机每个可用 awk 跑同一组用例，断言 stdout / stderr / 退出码与期望
#      逐字节一致；
#   3. 断言各实现之间输出完全相同（以第一个实现为基准逐用例比对）。
#
# 用例（四个都覆盖，含失败路径）：
#   main     正常语料 + 运行时合成的控制字符算例 → 有接受、有跳过，退出码 0
#   invalid  全部非法行 → 空 stdout + 跳过计数，退出码 1（决定 IPv6 族更新失败）
#   comments 只有注释与空行 → 空 stdout、空 stderr，退出码 1
#   empty    零字节输入 → 同 comments
#
# 注意「跨实现」只覆盖本机实际探测到的实现与版本：awk 只是命令名，可能指向
# gawk / mawk / nawk / BusyBox awk，各自版本的行为都有差异史。探测与显式
# AWK_LIST 都按「解析后的真实二进制」去重，因此 MIN_AWKS 计数的是不同的
# 可执行文件；同一实现的软链/别名不会凑数，但两个不同路径的同一实现也无法
# 自动识别，CI 里应显式列出已知互不相同的实现。
#
# 用法：
#   contrib/tests/awk-parity-check.sh [update-chnroute.sh 路径]
#   AWK_LIST='gawk|mawk|busybox awk' contrib/tests/awk-parity-check.sh
#   MIN_AWKS=2 contrib/tests/awk-parity-check.sh      # 少于此数视为失败
#   SELF_TEST=1 contrib/tests/awk-parity-check.sh     # 变异自检：见下
#
# 在 OpenWrt（真实运行环境）上验证：
#   scp update-chnroute.sh awk-parity-check.sh ipv6-corpus* /tmp/
#   AWK_LIST=awk SCRIPT=/tmp/update-chnroute.sh sh /tmp/awk-parity-check.sh
#
# SELF_TEST=1 会基于当前脚本生成一个故意改坏校验语义的变异体（组数上界
# 从 <8 放宽到 <=8），再以子进程跑一遍本测试，并要求它**因 main 用例 stdout
# 不匹配而失败**（而非因抽取出错、命令不存在等无关原因），用以证明断言不是
# 空跑。CI 里建议 MIN_AWKS>=2 且带上 SELF_TEST=1。
#
# 依赖：与生产脚本相同的运行环境——Linux / OpenWrt 等有 /dev/stderr 的 Unix
# （校验程序自身用 > "/dev/stderr" 写诊断，非 POSIX 保证）；本测试另用到
# mktemp -d、cmp、diff、readlink（可选，缺失时退化为按路径去重）。
#
# 退出码：所有实现都跑通且与期望一致为 0，否则 1。
# -------------------------------------------------------------------------

# 固定 C locale：awk 的字符串比较（区间方向校验依赖定长十六进制键的字典序）、
# toupper、tr、sed 的行为都不再受运行环境 locale 影响。
LC_ALL=C
export LC_ALL

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${1:-${SCRIPT:-$HERE/../usr/libexec/xtp-rs/update-chnroute.sh}}
CORPUS=$HERE/ipv6-corpus.txt
EXPECT_OUT=$HERE/ipv6-corpus.stdout
EXPECT_ERR=$HERE/ipv6-corpus.stderr
CORPUS_INVALID=$HERE/ipv6-corpus-invalid.txt
EXPECT_INVALID_ERR=$HERE/ipv6-corpus-invalid.stderr

die() {
  echo "[-] $*" >&2
  exit 1
}

[ -f "$SCRIPT" ] || die "script not found: $SCRIPT"
for _f in "$CORPUS" "$EXPECT_OUT" "$EXPECT_ERR" "$CORPUS_INVALID" "$EXPECT_INVALID_ERR"; do
  [ -f "$_f" ] || die "fixture not found: $_f"
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/xtp-awk-parity.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# 从脚本中抽取校验程序：AWK_PARITY_BEGIN / AWK_PARITY_END 是 awk 注释行，
# 位于 update_china_ip6s 的 awk 程序体内，标记之间的内容即完整程序。
extract_program() {
  sed -n '/AWK_PARITY_BEGIN/,/AWK_PARITY_END/p' "$SCRIPT" | sed '1d;$d' > "$TMP/prog.awk"
  [ -s "$TMP/prog.awk" ] || die "failed to extract awk program from $SCRIPT (missing AWK_PARITY markers?)"
  grep -q 'function ip6_ok' "$TMP/prog.awk" || die "extracted program looks wrong (ip6_ok not found): $TMP/prog.awk"
}

# 生产调用的 locale 必须被固定：本脚本自己 export 了 LC_ALL=C，而抽取出来的
# 只有程序体，所以「生产脚本忘了写 LC_ALL=C」这种行为回归无法被上面的用例发现。
# 又因为 C.UTF-8 对十六进制键的排序与 C 一致，行为测试同样区分不出来，只能查源码。
# 断言：紧邻 AWK_PARITY_BEGIN 之前的那条 awk 调用必须以 LC_ALL=C 开头。
check_production_locale() {
  _mark=$(grep -n 'AWK_PARITY_BEGIN' "$SCRIPT" | head -n 1 | cut -d: -f1)
  [ -n "$_mark" ] || die "cannot locate AWK_PARITY_BEGIN in $SCRIPT"
  _call=$(head -n "$_mark" "$SCRIPT" | grep -n "awk '" | tail -n 1 | cut -d: -f1)
  [ -n "$_call" ] || die "cannot locate the production awk invocation in $SCRIPT"
  if ! head -n "$_mark" "$SCRIPT" | sed -n "${_call}p" | grep -q 'LC_ALL=C[[:space:]]*awk'; then
    die "production awk invocation (line $_call of $SCRIPT) must be prefixed with LC_ALL=C"
  fi
}

# 组装四个用例的输入 / 期望 stdout / 期望 stderr / 期望退出码。
# main 的控制字符算例（制表符分隔、多空白、行尾 CR）在运行时拼进来，避免在
# 仓库文本文件里混入控制字符；三条均为合法区间，故只追加 stdout 期望。
build_cases() {
  {
    cat "$CORPUS"
    printf '\t240e:12::\t240e:13::\n'
    printf '  240e:10::   240e:11::   \n'
    printf '240e:14:: 240e:15::\r\n'
  } > "$TMP/case-main.in"
  {
    cat "$EXPECT_OUT"
    printf '      %s-%s,\n' '240e:12::' '240e:13::'
    printf '      %s-%s,\n' '240e:10::' '240e:11::'
    printf '      %s-%s,\n' '240e:14::' '240e:15::'
  } > "$TMP/case-main.out"
  cp "$EXPECT_ERR" "$TMP/case-main.err"
  echo 0 > "$TMP/case-main.rc"

  cp "$CORPUS_INVALID" "$TMP/case-invalid.in"
  : > "$TMP/case-invalid.out"
  cp "$EXPECT_INVALID_ERR" "$TMP/case-invalid.err"
  echo 1 > "$TMP/case-invalid.rc"

  cp "$HERE/ipv6-corpus-comments.txt" "$TMP/case-comments.in"
  : > "$TMP/case-comments.out"
  : > "$TMP/case-comments.err"
  echo 1 > "$TMP/case-comments.rc"

  : > "$TMP/case-empty.in"
  : > "$TMP/case-empty.out"
  : > "$TMP/case-empty.err"
  echo 1 > "$TMP/case-empty.rc"
}

# 把一条命令解析成真实二进制路径，用于去重（nawk -> gawk、awk -> busybox
# 这类软链不重复计数；readlink 缺失时退化为按命令解析出的路径比较）。
resolve_bin() {
  _bin=${1%% *}
  _path=$(command -v "$_bin" 2>/dev/null) || return 1
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$_path" 2>/dev/null || printf '%s\n' "$_path"
  else
    printf '%s\n' "$_path"
  fi
}

# 候选 awk 实现：显式 AWK_LIST 优先（同样去重），否则探测本机常见实现。
# 裸 awk 排在最后：Linux 上它通常软链到 gawk/mawk，前面已覆盖；OpenWrt 上
# 它就是 busybox awk。
detect_awks() {
  # 显式列表与自动探测的失败策略不同：显式列表视作「必须覆盖这些实现」的
  # 契约，缺一个就 fail-fast——否则 CI 指定 gawk|mawk|busybox 而某个不存在时，
  # 只要剩下的够 MIN_AWKS 就会静默通过，覆盖度与预期不符。
  if [ -n "${AWK_LIST:-}" ]; then
    _raw=$AWK_LIST
    _explicit=1
  else
    _raw='gawk|mawk|nawk|original-awk|busybox awk|awk'
    _explicit=0
  fi
  _list=""
  _seen=" "
  _seen_real=" "
  OLDIFS=$IFS
  IFS='|'
  for _cmd in $_raw; do
    IFS=$OLDIFS
    [ -n "$_cmd" ] || continue
    case "$_seen" in
      *" $_cmd "*) IFS='|'; continue ;;   # 同一串重复列出
    esac
    _seen="$_seen$_cmd "
    # busybox 未必编入 awk applet（精简构建常见），直接试跑一次而不是去猜
    # --list 的输出格式
    if [ "$_cmd" = "busybox awk" ]; then
      if ! busybox awk 'BEGIN { exit 0 }' >/dev/null 2>&1; then
        if [ "$_explicit" = 1 ]; then
          die "AWK_LIST entry unusable (busybox awk applet missing): $_cmd"
        fi
        IFS='|'
        continue
      fi
    fi
    if ! _real=$(resolve_bin "$_cmd"); then
      if [ "$_explicit" = 1 ]; then
        die "AWK_LIST entry not found: $_cmd"
      fi
      IFS='|'
      continue
    fi
    case "$_seen_real" in
      *" $_real "*) IFS='|'; continue ;;  # 不同写法但同一二进制
    esac
    _seen_real="$_seen_real$_real "
    _list="${_list}|${_cmd}"
    IFS='|'
  done
  IFS=$OLDIFS
  echo "${_list#|}"
}

probe_version() {
  # mawk 对未知长选项的报错是 "mawk: not an option: --version"（不是
  # "unrecognized option"），因此三种措辞都要认，否则会把它当成版本号打印。
  _v=$(sh -c "$1 --version 2>&1 | head -n 1" || true)
  case "$_v" in
    ''|*'unrecognized option'*|*'invalid option'*|*'not an option'*|*'ignored'*)
      _v=$(sh -c "$1 -W version 2>&1 | head -n 1" || true)
      ;;
  esac
  case "$_v" in
    ''|*'unrecognized option'*|*'invalid option'*|*'not an option'*|*'ignored'*) _v='(no version flag)' ;;
  esac
  printf '%s' "$_v"
}

extract_program
check_production_locale
build_cases

# 变异自检：故意放宽组数上界（<8 -> <=8），断言本测试会因 main 用例 stdout
# 不匹配而失败。只认 rc!=0 不够——抽取出错、命令不存在也会导致非零退出，
# 所以还要求子进程日志里出现 main 用例的 stdout 不匹配标记。
self_test() {
  grep -q 'return (nl + nr < 8)' "$SCRIPT" ||
    die "self-test: mutation anchor 'return (nl + nr < 8)' not found in $SCRIPT"
  sed 's/return (nl + nr < 8)/return (nl + nr <= 8)/' "$SCRIPT" > "$TMP/mutant.sh"
  cmp -s "$SCRIPT" "$TMP/mutant.sh" && die "self-test: mutation did not apply"

  # 先独立确认变异体是「语义改变」而不是「执行失败」：语法错、缺命令同样会让
  # 下面那次 harness 跑出非零退出和空 stdout。期望签名：退出码仍为 0、
  # stdout 恰好多接受 2 行（19+2=21）、跳过数从 16 减到 14。
  _awk0=${AWK_LIST%%|*}
  sed -n '/AWK_PARITY_BEGIN/,/AWK_PARITY_END/p' "$TMP/mutant.sh" | sed '1d;$d' > "$TMP/mutant.awk"
  _mrc=0
  sh -c "$_awk0 -f '$TMP/mutant.awk' '$TMP/case-main.in'" \
    > "$TMP/mutant.main.out" 2> "$TMP/mutant.main.err" || _mrc=$?
  [ "$_mrc" -eq 0 ] || die "self-test: mutant exited $_mrc (crash, not a semantic change): $(cat "$TMP/mutant.main.err")"
  _want=$(( $(wc -l < "$TMP/case-main.out") + 2 ))
  _got=$(wc -l < "$TMP/mutant.main.out")
  [ "$_got" -eq "$_want" ] || die "self-test: mutant accepted $_got lines, expected $_want (semantic signature mismatch)"
  grep -q 'skipped 14 invalid line(s)' "$TMP/mutant.main.err" ||
    die "self-test: mutant skip count is not 14 (semantic signature mismatch): $(cat "$TMP/mutant.main.err")"

  # 再要求完整 harness 因 main 用例 stdout 不匹配而失败
  _rc=0
  SELF_TEST=0 sh "$0" "$TMP/mutant.sh" > "$TMP/mutant.log" 2>&1 || _rc=$?
  [ "$_rc" -ne 0 ] || {
    cat "$TMP/mutant.log" >&2
    die "self-test: mutant NOT detected, assertions are vacuous"
  }
  grep -q 'MISMATCH:.*main:stdout' "$TMP/mutant.log" || {
    cat "$TMP/mutant.log" >&2
    die "self-test: mutant failed for an unexpected reason (no 'main:stdout' mismatch)"
  }
  echo "[+] self-test: mutant (nl+nr<=8) changes semantics (rc=0, +2 accepted, skipped 14) and is rejected"
}

AWK_LIST=$(detect_awks)
[ -n "$AWK_LIST" ] || die "no awk implementation found (set AWK_LIST)"

if [ "${SELF_TEST:-0}" = "1" ]; then
  self_test
fi

CASES='main invalid comments empty'

echo "[*] script : $SCRIPT"
echo "[*] program: $TMP/prog.awk ($(wc -l < "$TMP/prog.awk") lines, extracted)"
echo "[*] cases  : $CASES (main: $(wc -l < "$TMP/case-main.in") lines," \
  "$(wc -l < "$TMP/case-main.out") accepted /" \
  "$(sed -n 's/^.*skipped \([0-9]*\).*$/\1/p' "$TMP/case-main.err") skipped)"
echo "[*] expect : invalid → $(sed -n 's/^.*skipped \([0-9]*\).*$/\1/p' "$TMP/case-invalid.err")" \
  "skipped + rc 1; comments/empty → rc 1 with empty output"

FAILED=0
COUNT=0
OLDIFS=$IFS
IFS='|'
for _cmd in $AWK_LIST; do
  IFS=$OLDIFS
  COUNT=$((COUNT + 1))
  # 标签带上序号，避免不同命令串经 tr 归一后撞名而互相覆盖输出文件
  _tag="${COUNT}_$(printf '%s' "$_cmd" | tr -c 'A-Za-z0-9' '_')"
  printf '[%s] %-20s %s\n' '*' "$_cmd" "$(probe_version "$_cmd")"

  _bad=""
  for _case in $CASES; do
    _want_rc=$(cat "$TMP/case-$_case.rc")
    _rc=0
    sh -c "$_cmd -f '$TMP/prog.awk' '$TMP/case-$_case.in'" \
      > "$TMP/$_tag.$_case.out" 2> "$TMP/$_tag.$_case.err" || _rc=$?
    [ "$_rc" -eq "$_want_rc" ] || _bad="$_bad,$_case:exit=$_rc(want $_want_rc)"
    cmp -s "$TMP/case-$_case.out" "$TMP/$_tag.$_case.out" || _bad="$_bad,$_case:stdout"
    cmp -s "$TMP/case-$_case.err" "$TMP/$_tag.$_case.err" || _bad="$_bad,$_case:stderr"
    if [ -d "$TMP/ref" ]; then
      cmp -s "$TMP/ref/$_case.out" "$TMP/$_tag.$_case.out" || _bad="$_bad,$_case:not-identical-to-others"
    fi
  done

  if [ -z "$_bad" ]; then
    echo "[+]     all $CASES cases identical to expected"
    if [ ! -d "$TMP/ref" ]; then
      mkdir -p "$TMP/ref"
      for _case in $CASES; do
        cp "$TMP/$_tag.$_case.out" "$TMP/ref/$_case.out"
      done
    fi
  else
    FAILED=$((FAILED + 1))
    echo "[-]     MISMATCH:${_bad#,}" >&2
    for _case in $CASES; do
      diff -u "$TMP/case-$_case.out" "$TMP/$_tag.$_case.out" >&2 || true
      diff -u "$TMP/case-$_case.err" "$TMP/$_tag.$_case.err" >&2 || true
    done
  fi
  IFS='|'
done
IFS=$OLDIFS

if [ "$FAILED" -ne 0 ]; then
  echo "[-] $FAILED/$COUNT implementation(s) mismatch" >&2
  exit 1
fi

MIN_AWKS=${MIN_AWKS:-1}
if [ "$COUNT" -lt "$MIN_AWKS" ]; then
  echo "[-] only $COUNT distinct awk binary(ies) found, but MIN_AWKS=$MIN_AWKS requires more" >&2
  exit 1
fi

if [ "$COUNT" -eq 1 ]; then
  echo "[!] single implementation: output matches expected, but cross-implementation" \
    "parity was NOT verified (install gawk/mawk or set AWK_LIST for a real comparison)"
  exit 0
fi

echo "[+] all $COUNT awk implementation(s) agree across $CASES cases and match expected output"
