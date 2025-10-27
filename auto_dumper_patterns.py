import idaapi
import ida_bytes
import ida_ua
import ida_funcs
import idautils
import idc
import struct
import json
import os

def find_string_ea(text):
    for s in idautils.Strings():
        if str(s) == text:
            return int(s.ea)
    for s in idautils.Strings():
        ss = str(s)
        if ss.startswith(text):
            return int(s.ea)
    return idc.BADADDR

def get_code_xrefs(ea):
    xs = []
    for xr in idautils.XrefsTo(ea):
        if idaapi.is_code(ida_bytes.get_full_flags(xr.frm)):
            xs.append(int(xr.frm))
    return sorted(set(xs))

def wildcard_map_for_insn(insn, size):
    wild = set()
    bs = ida_bytes.get_bytes(insn.ea, size) or b""
    if len(bs) >= 5 and bs[0] in (0xE8, 0xE9):
        for j in range(size - 4, size):
            wild.add(j)
    if len(bs) >= 7 and bs[:3] == b"\x48\x8D\x0D":
        for j in range(3, 7):
            wild.add(j)
    if len(bs) >= 7 and bs[0] == 0x48 and bs[1] == 0x89 and (bs[2] & 0xC7) == 0x05:
        for j in range(3, 7):
            wild.add(j)
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            continue
        offb = getattr(op, "offb", 255)
        offo = getattr(op, "offo", 0)
        if offb != 255 and offo > 0:
            for j in range(offb, min(offb + offo, size)):
                wild.add(j)
    return wild

def collect_pattern_bytes(ea, insn_count):
    buf = []
    mask = []
    cur = ea
    for _ in range(insn_count):
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, cur)
        if sz <= 0:
            break
        bs = ida_bytes.get_bytes(cur, sz)
        if not bs:
            break
        wild = wildcard_map_for_insn(insn, sz)
        for i in range(sz):
            bi = bs[i] if isinstance(bs[i], int) else ord(bs[i])
            if i in wild:
                buf.append(0)
                mask.append(0)
            else:
                buf.append(bi)
                mask.append(1)
        cur += sz
    return buf, mask

def to_ida_pattern(buf, mask):
    return " ".join("??" if m == 0 else "{:02X}".format(b) for b, m in zip(buf, mask))

def exec_ranges():
    out = []
    s = idaapi.get_first_seg()
    while s:
        if s.perm & idaapi.SEGPERM_EXEC:
            out.append((int(s.start_ea), int(s.end_ea)))
        s = idaapi.get_next_seg(s.start_ea)
    return out

def count_occurrences_compiled(buf, mask):
    n = len(buf)
    if n == 0:
        return 0
    cnt = 0
    for start, end in exec_ranges():
        ea = start
        while ea + n <= end:
            bs = ida_bytes.get_bytes(ea, n)
            if not bs:
                break
            ok = True
            for i in range(n):
                bi = bs[i] if isinstance(bs[i], int) else ord(bs[i])
                if mask[i] == 1 and bi != buf[i]:
                    ok = False
                    break
            if ok:
                cnt += 1
            ea += 1
    return cnt

def unique_pattern_from_ea(ea, min_insns=2, max_insns=16):
    best = ""
    for k in range(min_insns, max_insns + 1):
        buf, mask = collect_pattern_bytes(ea, k)
        if not buf:
            break
        pat = to_ida_pattern(buf, mask)
        if count_occurrences_compiled(buf, mask) == 1:
            return pat
        best = pat
    return best

def func_start(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else idc.BADADDR

patterns_out = {}

def save_pattern(key, pat):
    if key and pat:
        patterns_out[key] = pat

STRING_LABEL_TO_KEY = {
    "version-": "pattern_version",
    "Valex [V5] ROBLOX (LIVE) {PUBLISH}": "pattern_str_ref",
    "Valex::core": "Valex::core_str",
    "Valex::auth": "Valex::auth_str",
    "Valex::tp_handler": "Valex::tp_handler_str",
    "Valex::shutdown": "Valex::shutdown_str",
    "Valex::players": "Valex::players_str",
    "Valex::crash": "Valex::crash_str",
    "Valex::security": "Valex::security_str",
    "Valex::bypass": "Valex::bypass_str",
}

STRING_LABEL_TO_FUNC_KEY = {
    "Valex::shutdown": "Valex::shutdown_function",
    "Valex::crash": "Valex::crash_function",
}

def func_sig_pattern(func_ea, bytes_limit=96):
    if func_ea == idc.BADADDR:
        return ""
    out = []
    cur = func_ea
    total = 0
    while total < bytes_limit:
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, cur)
        if sz <= 0:
            break
        bs = ida_bytes.get_bytes(cur, sz)
        if not bs:
            break
        wild = wildcard_map_for_insn(insn, sz)
        for i in range(sz):
            bi = bs[i] if isinstance(bs[i], int) else ord(bs[i])
            out.append("??" if i in wild else "{:02X}".format(bi))
        total += sz
        cur += sz
    return " ".join(out)

def next_direct_call_after(ea, max_insns=200):
    cur = ea
    for _ in range(max_insns):
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, cur)
        if sz <= 0:
            return idc.BADADDR, idc.BADADDR
        bs = ida_bytes.get_bytes(cur, sz) or b""
        if len(bs) >= 5 and bs[0] == 0xE8:
            rel = struct.unpack("<i", bs[1:5])[0]
            tgt = cur + sz + rel
            return cur, tgt
        cur += sz
    return idc.BADADDR, idc.BADADDR

def find_nth_direct_call_after(ea, n, max_insns=800, end_ea=None):
    cur = ea
    found = 0
    while True:
        if end_ea is not None and cur >= end_ea:
            return idc.BADADDR, idc.BADADDR
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, cur)
        if sz <= 0:
            return idc.BADADDR, idc.BADADDR
        bs = ida_bytes.get_bytes(cur, sz) or b""
        if len(bs) >= 5 and bs[0] == 0xE8:
            found += 1
            rel = struct.unpack("<i", bs[1:5])[0]
            tgt = cur + sz + rel
            if found == n:
                return cur, tgt
        cur += sz

def find_jnz_after(ea, max_insns=300):
    cur = ea
    saw_test = False
    for _ in range(max_insns):
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, cur)
        if sz <= 0:
            return idc.BADADDR
        bs = ida_bytes.get_bytes(cur, sz) or b""
        if not saw_test and len(bs) >= 2 and bs[0] == 0x84 and bs[1] == 0xC0:
            saw_test = True
        elif saw_test and len(bs) >= 2 and bs[0] == 0x0F and bs[1] == 0x85:
            return cur
        cur += sz
    return idc.BADADDR

def func_has_string(fea, text):
    se = find_string_ea(text)
    if se == idc.BADADDR:
        return False
    for xr in idautils.XrefsTo(se):
        if func_start(int(xr.frm)) == fea:
            return True
    return False

def func_calls_api(fea, api_base):
    for name in (api_base + "A", api_base + "W", api_base):
        ea = idc.get_name_ea_simple(name)
        if ea == idc.BADADDR:
            continue
        for caller in idautils.CodeRefsTo(ea, 0):
            if func_start(caller) == fea:
                return True
    return False

def jcc_target(ea):
    bs = ida_bytes.get_bytes(ea, 6) or b""
    if len(bs) >= 6 and bs[0] == 0x0F and bs[1] in (0x84, 0x85):
        rel = struct.unpack("<i", bs[2:6])[0]
        return ea + 6 + rel
    if len(bs) >= 2 and bs[0] in (0x74, 0x75):
        rel8 = struct.unpack("<b", bs[1:2])[0]
        return ea + 2 + rel8
    return idc.BADADDR

def bb_contains_string(start_ea, text, span_insns=64):
    se = find_string_ea(text)
    if se == idc.BADADDR:
        return False
    end = start_ea
    for _ in range(span_insns):
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, end)
        if sz <= 0:
            break
        end += sz
    for xr in idautils.XrefsTo(se):
        x = int(xr.frm)
        if start_ea <= x < end:
            return True
    return False

def dump_for_string(label, also_func=False):
    s_ea = find_string_ea(label)
    if s_ea == idc.BADADDR:
        print(f"{label} none")
        return
    xrefs = get_code_xrefs(s_ea)
    if not xrefs:
        print(f"{label} no_xrefs")
        return
    for idx, ea in enumerate(xrefs):
        pat = unique_pattern_from_ea(ea, 2, 16)
        print(f"{label}#{idx} 0x{ea:X} {pat}")
        if idx == 0 and label in STRING_LABEL_TO_KEY:
            save_pattern(STRING_LABEL_TO_KEY[label], pat)
        if also_func:
            fea = func_start(ea)
            if fea != idc.BADADDR:
                fpat = func_sig_pattern(fea, 64)
                print(f"{label}#{idx}:func 0x{fea:X} {fpat}")
                if idx == 0 and label in STRING_LABEL_TO_FUNC_KEY:
                    save_pattern(STRING_LABEL_TO_FUNC_KEY[label], fpat)

def dump_auth_callee_func_named():
    s_ea = find_string_ea("Valex::auth")
    if s_ea == idc.BADADDR:
        print("Valex::print_function_color_time_function none")
        return
    printed_funcs = set()
    for ea in get_code_xrefs(s_ea):
        call_ea, tgt = next_direct_call_after(ea, 300)
        if call_ea == idc.BADADDR or tgt == idc.BADADDR:
            continue
        f = ida_funcs.get_func(tgt)
        fea = int(f.start_ea) if f else tgt
        if fea in printed_funcs:
            continue
        fpat = func_sig_pattern(fea, 96)
        print(f"Valex::print_function_color_time_function 0x{fea:X} {fpat}")
        save_pattern("Valex::print_function_color_time_function", fpat)
        printed_funcs.add(fea)
        break

def run():
    dump_for_string("version-", False)
    dump_for_string("Valex [V5] ROBLOX (LIVE) {PUBLISH}", False)
    dump_for_string("Valex::core", False)
    dump_for_string("Valex::auth", False)
    dump_for_string("Valex::tp_handler", False)
    dump_for_string("Valex::shutdown", True)
    dump_for_string("Valex::players", False)
    dump_for_string("Valex::crash", True)
    dump_for_string("Valex::security", False)
    dump_for_string("Valex::bypass", False)
    dump_for_string("Valex::manager", False)
    dump_for_string("Valex::configs", False)
    dump_auth_callee_func_named()
    dump_d3dcompiler_links_jnz()

def dump_config_init_2nd_and_jnz():
    se = find_string_ea("Config initialized.")
    if se == idc.BADADDR:
        print("config_init no string")
        return
    for xr in idautils.XrefsTo(se):
        xea = int(xr.frm)
        f = ida_funcs.get_func(xea)
        fend = int(f.end_ea) if f else None
        if not f:
            continue
        if not func_has_string(int(f.start_ea), "Please open Roblox before running Valex"):
            continue
        call_ea, tgt = find_nth_direct_call_after(xea, 2, 800, fend)
        if call_ea == idc.BADADDR:
            continue
        fea = func_start(tgt)
        if fea == idc.BADADDR:
            fea = tgt
        if not func_has_string(fea, "Valex Loader"):
            continue
        if not func_calls_api(fea, "SetConsoleTitle"):
            continue
        pat_call = unique_pattern_from_ea(call_ea, 2, 16)
        print(f"check_key_call 0x{call_ea:X} {pat_call}")
        save_pattern("check_key_call", pat_call)
        jnz_ea = find_jnz_after(call_ea, 200)
        if jnz_ea == idc.BADADDR:
            print("jnz_check_key_2 none")
            return
        pat_jnz = unique_pattern_from_ea(jnz_ea, 1, 8)
        print(f"jnz_check_key_2 0x{jnz_ea:X} {pat_jnz}")
        save_pattern("jnz_check_key_2", pat_jnz)
        tgt_bb = jcc_target(jnz_ea)
        if tgt_bb != idc.BADADDR and bb_contains_string(tgt_bb, "Authentication successful.", 128):
            pat_auth = unique_pattern_from_ea(tgt_bb, 8, 32)
            print(f"Authentication_successfull 0x{tgt_bb:X} {pat_auth}")
            save_pattern("Authentication_successfull", pat_auth)
        fobj = ida_funcs.get_func(fea)
        if fobj:
            target_name_ea = idc.get_name_ea_simple("sub_1400CA350")
            cur = int(fobj.start_ea)
            end = int(fobj.end_ea)
            cin_count = 0
            while cur < end:
                insn = ida_ua.insn_t()
                sz = ida_ua.decode_insn(insn, cur)
                if sz <= 0:
                    break
                bs = ida_bytes.get_bytes(cur, sz) or b""
                if len(bs) >= 5 and bs[0] == 0xE8:
                    rel = struct.unpack("<i", bs[1:5])[0]
                    tgt = cur + sz + rel
                    fea2 = func_start(tgt)
                    if target_name_ea != idc.BADADDR and fea2 != idc.BADADDR and fea2 == target_name_ea:
                        cin_count += 1
                        if cin_count == 2:
                            pat_cin = unique_pattern_from_ea(cur, 2, 12)
                            print(f"UserInput_key_std_cin 0x{cur:X} {pat_cin}")
                            save_pattern("UserInput_key_std_cin", pat_cin)
                            break
                cur += sz
            cur = int(fobj.start_ea)
            end = int(fobj.end_ea)
            window = []
            found = False
            cin_count = 0
            while cur < end:
                insn = ida_ua.insn_t()
                sz = ida_ua.decode_insn(insn, cur)
                if sz <= 0:
                    break
                bs = ida_bytes.get_bytes(cur, sz) or b""
                is_lea_rdx_rsp = False
                if len(bs) >= 4 and bs[0] == 0x48 and bs[1] == 0x8D and (bs[2] & 0x38) == 0x10 and (bs[2] & 0x07) == 0x04 and (len(bs) < 4 or (bs[3] & 0x07) == 0x04):
                    is_lea_rdx_rsp = True
                is_mov_rcx_rip = False
                is_cin = False
                if len(bs) >= 7 and bs[0] == 0x48 and bs[1] == 0x8B and bs[2] == 0x0D:
                    rel = struct.unpack("<i", bs[3:7])[0]
                    rip = cur + sz
                    tgt = rip + rel
                    nm = idc.get_name(tgt) or ""
                    is_mov_rcx_rip = True
                    if "cin@std" in nm or "?cin@std@@" in nm:
                        is_cin = True
                    else:
                        is_cin = True
                is_call = len(bs) >= 5 and bs[0] == 0xE8
                window.append((cur, sz, is_lea_rdx_rsp, is_mov_rcx_rip, is_cin, is_call))
                if len(window) > 12:
                    window.pop(0)
                if is_call:
                    has_cin = any(w[4] for w in window)
                    has_lea = any(w[2] for w in window)
                    if has_cin and has_lea:
                        cin_count += 1
                        if cin_count == 2:
                            pat_cin = unique_pattern_from_ea(cur, 2, 12)
                            print(f"UserInput_key_std_cin 0x{cur:X} {pat_cin}")
                            save_pattern("UserInput_key_std_cin", pat_cin)
                            found = True
                            break
                cur += sz
            if not found:
                cur = int(fobj.start_ea)
                cin_count = 0
                while cur < end:
                    insn = ida_ua.insn_t()
                    sz = ida_ua.decode_insn(insn, cur)
                    if sz <= 0:
                        break
                    bs = ida_bytes.get_bytes(cur, sz) or b""
                    if len(bs) >= 5 and bs[0] == 0xE8:
                        nxt = cur + sz
                        insn2 = ida_ua.insn_t()
                        sz2 = ida_ua.decode_insn(insn2, nxt)
                        if sz2 > 0:
                            bs2 = ida_bytes.get_bytes(nxt, sz2) or b""
                            if len(bs2) >= 5 and bs2[0] == 0x48 and bs2[1] == 0x8D and bs2[2] == 0x44 and bs2[3] == 0x24:
                                cin_count += 1
                                if cin_count == 2:
                                    pat_cin = unique_pattern_from_ea(cur, 2, 12)
                                    print(f"UserInput_key_std_cin 0x{cur:X} {pat_cin}")
                                    save_pattern("UserInput_key_std_cin", pat_cin)
                                    break
                    cur += sz
        return
    print("config_init not found")

def dump_d3dcompiler_links_jnz():
    se = find_string_ea("d3dcompiler_43.dll")
    if se == idc.BADADDR:
        print("pattern_jnz_before_links none")
        return
    for xr in idautils.XrefsTo(se):
        xea = int(xr.frm)
        f = ida_funcs.get_func(xea)
        fend = int(f.end_ea) if f else None
        cur = xea
        call_ea = idc.BADADDR
        state = 0
        while fend is None or cur < fend:
            insn = ida_ua.insn_t()
            sz = ida_ua.decode_insn(insn, cur)
            if sz <= 0:
                break
            bs = ida_bytes.get_bytes(cur, sz) or b""
            if state == 0:
                if cur == xea:
                    state = 1
            elif state == 1:
                tgt = idc.BADADDR
                kind = None
                if len(bs) >= 6 and bs[0] == 0xFF and (bs[1] & 0xF8) == 0x10:
                    disp = struct.unpack("<i", bs[2:6])[0]
                    rip = cur + sz
                    iat = rip + disp
                    nm = idc.get_name(iat) or ""
                    if "LoadLibraryA" in nm:
                        call_ea = cur
                        state = 2
                elif len(bs) >= 5 and bs[0] == 0xE8:
                    rel = struct.unpack("<i", bs[1:5])[0]
                    tgt = cur + sz + rel
                    nm = idc.get_name(func_start(tgt)) or idc.get_name(tgt) or ""
                    if "LoadLibraryA" in nm:
                        call_ea = cur
                        state = 2
            elif state == 2:
                if (len(bs) >= 3 and bs[0] == 0x48 and bs[1] == 0x85 and bs[2] == 0xC0) or (len(bs) >= 2 and bs[0] == 0x85 and bs[1] == 0xC0):
                    pass
                elif (len(bs) >= 2 and bs[0] in (0x75,)) or (len(bs) >= 6 and bs[0] == 0x0F and bs[1] == 0x85):
                    jnz_ea = cur
                    pat_jnz = unique_pattern_from_ea(jnz_ea, 2, 10)
                    print(f"pattern_jnz_before_links 0x{jnz_ea:X} {pat_jnz}")
                    save_pattern("pattern_jnz_before_links", pat_jnz)
                    tgt = jcc_target(jnz_ea)
                    if tgt != idc.BADADDR:
                        pat_tgt = unique_pattern_from_ea(tgt, 8, 28)
                        print(f"pattern_target_jnz_links 0x{tgt:X} {pat_tgt}")
                        save_pattern("pattern_target_jnz_links", pat_tgt)
                    return
            cur += sz
    print("pattern_jnz_before_links none")

if __name__ == "__main__":
    print("---------------")
    run()
    dump_config_init_2nd_and_jnz()
    dump_d3dcompiler_links_jnz()
    try:
        try:
            here = os.path.dirname(__file__)
        except NameError:
            here = os.getcwd()
        out_path = os.path.join(here, "patterns_generated.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(patterns_out, f, indent=2, ensure_ascii=False)
        print(f"json_out {out_path} {len(patterns_out)}")
    except Exception as e:
        print(f"json_out error {e}")