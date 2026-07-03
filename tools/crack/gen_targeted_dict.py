#!/usr/bin/env python3
"""
基于路由器硬件信息生成定向字典
利用 MAC / SN / CMEI 的各种子串变换来缩小搜索空间
使用前请修改下方的配置
"""

import itertools
import re

# ============ 配置区 ============
# 路由器标签上的硬件信息（用于生成定向候选）
MAC = "AABBCCDDEEFF"        # 路由器 MAC 地址（12位hex，无冒号）
SN = "XXXXXXXXXXXX"         # 序列号
CMEI = "000000000000000"    # CMEI（如果有的话）
BSSID = "AABBCCDDEEFF"      # BSSID（通常和 MAC 相同）

# 已知的密码字符信息（知道多少填多少，不知道留空字符串）
# 格式: 8位密码，第 1-6 位是字母，第 7 位是数字，第 8 位是字母
KNOWN_DIGIT = ""            # 第 7 位（倒数第二位）的数字 0-9，不知道留空
KNOWN_LAST_CHAR = ""        # 第 8 位（最后一位）的字母 a-z，不知道留空
KNOWN_PREFIX = ""           # 已知的开头字母（最多6位），不知道留空
# ================================


def match_format(s: str) -> bool:
    """检查字符串是否符合已知的密码格式"""
    if len(s) != 8:
        return False
    # 前 6 位必须是小写字母
    for i in range(6):
        if not s[i].islower():
            return False
    # 第 7 位必须是数字
    if not s[6].isdigit():
        return False
    # 第 8 位必须是小写字母
    if not s[7].islower():
        return False
    # 已知数字检查
    if KNOWN_DIGIT and s[6] != KNOWN_DIGIT:
        return False
    # 已知末位检查
    if KNOWN_LAST_CHAR and s[7] != KNOWN_LAST_CHAR:
        return False
    # 已知前缀检查
    if KNOWN_PREFIX:
        if not s.startswith(KNOWN_PREFIX):
            return False
    return True


def add_if_valid(lst: list, s: str):
    if match_format(s):
        lst.append(s)


def generate_candidates():
    """基于硬件编号生成候选密码"""
    candidates = []
    mac_lower = MAC.lower()
    sn_lower = SN.lower()
    sn_digits = re.sub(r'[^0-9]', '', SN)

    # 1. MAC 地址 8 字符滑窗
    for i in range(len(mac_lower) - 7):
        add_if_valid(candidates, mac_lower[i:i+8])

    # 2. SN 纯数字 8 字符滑窗
    for i in range(len(sn_digits) - 7):
        add_if_valid(candidates, sn_digits[i:i+8])

    # 3. SN 原始 8 字符滑窗
    for i in range(len(sn_lower) - 7):
        add_if_valid(candidates, sn_lower[i:i+8])

    # 4. CMEI 滑窗
    for i in range(len(CMEI) - 7):
        add_if_valid(candidates, CMEI[i:i+8])

    # 5. MAC + SN 混合
    add_if_valid(candidates, mac_lower[6:12] + sn_digits[:2])
    add_if_valid(candidates, mac_lower[8:14] + sn_digits[:2])
    add_if_valid(candidates, sn_digits[:6] + mac_lower[12:14])

    # 6. 常见运营商前缀 + 后缀
    prefixes = ["cmcc", "CMCC", "Cmcc", "cMcc", "mercury", "MERCURY",
                "yr1901g", "wifi", "admin", "merc", "cmc", "yr"]
    suffixes = [mac_lower[-4:], sn_digits[-4:], CMEI[-4:]]
    for prefix in prefixes:
        for suffix in suffixes:
            add_if_valid(candidates, (prefix + suffix).lower()[:8])

    # 7. BSSID 分段组合
    if len(mac_lower) >= 12:
        bssid_parts = [mac_lower[i:i+2] for i in range(0, 12, 2)]
        add_if_valid(candidates, bssid_parts[0] + bssid_parts[2] + bssid_parts[4][:2])
        add_if_valid(candidates, bssid_parts[1] + bssid_parts[3] + bssid_parts[5][:2])

    # 8. SN 分段直接取
    add_if_valid(candidates, sn_lower[:8])
    if len(sn_lower) >= 12:
        add_if_valid(candidates, sn_lower[4:12])
        add_if_valid(candidates, sn_lower[5:13])

    # 9. 6 字母 + 数字 + 末字母 模式（基于 MAC/SN 字母片段）
    digit = KNOWN_DIGIT if KNOWN_DIGIT else "0"
    last = KNOWN_LAST_CHAR if KNOWN_LAST_CHAR else "a"

    def build_pattern6(letters6: str):
        return letters6 + digit + last

    # 从 MAC 提取 6 字母片段
    for i in range(len(mac_lower) - 5):
        seg = mac_lower[i:i+6]
        if all(c.islower() for c in seg):
            add_if_valid(candidates, build_pattern6(seg))

    # 从 SN 提取 6 字母片段
    sn_letters = re.sub(r'[^a-z]', '', sn_lower)
    for i in range(len(sn_letters) - 5):
        seg = sn_letters[i:i+6]
        add_if_valid(candidates, build_pattern6(seg))

    # 常见前缀 + 数字 + 末字母
    for prefix in ["cmcc", "mercury", "yr1901g", "wifi", "admin", "merc", "cmc", "yr"]:
        p6 = (prefix + "aaaaaa")[:6]
        # 如果知道数字和末字母，生成所有可能的中间组合
        if KNOWN_DIGIT and KNOWN_LAST_CHAR:
            add_if_valid(candidates, p6 + KNOWN_DIGIT + KNOWN_LAST_CHAR)

    # 10. 数字替换变体（0->o, 1->l, 2->z, 3->e, 4->a, 5->s, 6->g, 7->t, 8->b, 9->g）
    digit_map = {'0':'o','1':'l','2':'z','3':'e','4':'a','5':'s','6':'g','7':'t','8':'b','9':'g'}
    for src in [mac_lower, sn_lower]:
        for i in range(len(src) - 5):
            seg = list(src[i:i+6])
            for j in range(len(seg)):
                if seg[j].isdigit():
                    seg[j] = digit_map.get(seg[j], 'a')
            pwd = "".join(seg) + digit + last
            add_if_valid(candidates, pwd)

    # 去重
    unique = list(dict.fromkeys(candidates))
    return unique


def generate_smart_variations(base_list):
    """对基础候选做智能变体（字母数字替换）"""
    results = set()
    for s in base_list:
        results.add(s)
        subs = {
            'o': '0', 'i': '1', 'l': '1',
            's': '5', 'a': '4', 'e': '3'
        }
        for ch, rep in subs.items():
            if ch in s[:6]:
                results.add(s.replace(ch, rep, 1))
    return [r for r in results if match_format(r)]


if __name__ == "__main__":
    print("[*] 基于路由器硬件信息生成定向字典...")
    print(f"    MAC:  {MAC}")
    print(f"    SN:   {SN}")
    print(f"    CMEI: {CMEI}")
    if KNOWN_DIGIT:
        print(f"    已知第7位数字: {KNOWN_DIGIT}")
    if KNOWN_LAST_CHAR:
        print(f"    已知末位字母: {KNOWN_LAST_CHAR}")
    print()

    base = generate_candidates()
    print(f"[+] 基础候选: {len(base)} 个")

    smart = generate_smart_variations(base)
    print(f"[+] 智能变体后: {len(smart)} 个")

    with open("targeted_dict.txt", "w") as f:
        for pwd in smart:
            f.write(pwd + "\n")

    print(f"[+] 已保存到 targeted_dict.txt")
    print()

    if smart:
        print("前 20 个候选密码:")
        for pwd in smart[:20]:
            print(f"    {pwd}")
