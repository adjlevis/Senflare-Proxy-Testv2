#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Senflare Proxy Test —— Cloudflare ProxyIP 聚合 / 测试脚本 —— 多源汇聚 + DNS自动同步 + 消息通知

标准库，Python 3.8+。
"""

import io
import ipaddress
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import OrderedDict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode
from SourceParse import parse_source

# 控制台输出统一为 UTF-8
for _stream in (sys.stdout, sys.stderr):
    if isinstance(_stream, io.TextIOWrapper):
        _stream.reconfigure(encoding='utf-8', errors='replace')

# ============================================================================
# 一、配置列表
# ============================================================================

# —— 免测数据源（上游已有实测流水线，跳过 A×B 判定，直入主产物）——
DIRECT_SOURCES = {
    # 项目作者：Xiaobei09
    # 项目地址：https://github.com/Xiaobei09/proxyip
    'Xiaobei': {
        'url': 'https://raw.githubusercontent.com/Xiaobei09/proxyip/refs/heads/main/data/valid/all.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/Xiaobei09/proxyip@main/data/valid/all.txt',
    },
    # 项目作者：Fangsia Karlina
    # 项目地址：https://github.com/papapapapdelesia/Emilia
    'Fangsia Karlina': {
        'url': 'https://raw.githubusercontent.com/papapapapdelesia/Emilia/refs/heads/main/Data/alive.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/papapapapdelesia/Emilia@main/Data/alive.txt',
        'columns': (0, 1, 2, False),
    },
}

# —— 待测数据源（走 A×B 四格判定）——
TEST_SOURCES = {
    # 项目作者：Xgonce
    # 项目地址：https://github.com/xgonce/Cloudflare_IP
    'Xgonce': {
        'url': 'https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/xgonce/Cloudflare_IP@main/result.csv',
        'columns': (0, 2, 4, True),
    },
    # 项目作者：Lzj（辣子鸡）
    # 项目地址：https://github.com/wanwushequ/cfyxip
    'Lzj': {
        'url': 'https://raw.githubusercontent.com/wanwushequ/cfyxip/refs/heads/main/lzj/all.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/wanwushequ/cfyxip@main/lzj/all.txt',
    },
    # 项目作者：Wan828963-code
    # 项目地址：https://github.com/wan828963-code/best-cf-ips
    'Wan828963-code': {
        'url': 'https://raw.githubusercontent.com/wan828963-code/best-cf-ips/refs/heads/main/best-cf-ipv4.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/wan828963-code/best-cf-ips@main/best-cf-ipv4.txt',
    },
    # 项目作者：Alphaxzj
    # 项目地址：https://github.com/alphaxzj/bestcf
    'Alphaxzj': {
        'url': 'https://raw.githubusercontent.com/alphaxzj/bestcf/refs/heads/main/ipv4.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/alphaxzj/bestcf@main/ipv4.txt',
    },
    # 项目作者：Rxsweet
    # 项目地址：https://github.com/rxsweet/cfip
    'Rxsweet': {
        'url': 'https://raw.githubusercontent.com/rxsweet/cfip/refs/heads/main/ip/allip.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/rxsweet/cfip@main/ip/allip.txt',
    },
    # 项目作者：Liyan1972
    # 项目地址：https://github.com/liyan1972/proxyip-fetcher
    'Liyan1972': {
        'url': 'https://raw.githubusercontent.com/liyan1972/proxyip-fetcher/refs/heads/main/ProxyIP-asn-ips.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/liyan1972/proxyip-fetcher@main/ProxyIP-asn-ips.txt',
    },
    # 项目作者：NiREvil
    # 项目地址：https://github.com/NiREvil/vless
    'NiREvil': {
        'url': 'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/country_proxies/03_proxies.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/NiREvil/vless@main/sub/country_proxies/03_proxies.txt',
    },
    # 项目作者：OTC
    # 项目地址：https://github.com/avotcorg/proxy
    'OTC': {
        'url': 'https://raw.githubusercontent.com/avotcorg/proxy/refs/heads/main/ProxyList1.txt',
        'fallbackUrl': 'https://cdn.jsdelivr.net/gh/avotcorg/proxy@main/ProxyList1.txt',
        'columns': (0, 1, 2, False),
    },
}
# 输出/缓存锚定到脚本所在目录
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

FETCH_RETRIES = 5
FETCH_RETRY_DELAY = 2      # 相邻两次拉取之间的等待（秒）
FETCH_TIMEOUT = 10         # 数据源拉取超时（秒）

# —— A 入口能力（外部 TLS+SNI）——
ENTRY_TIMEOUT = 5       # 单节点超时（秒）
ENTRY_WORKERS = 200
ENTRY_TRIES = 1           # 每节点最多试几次，任一次成功即通过
ENTRY_RETRY_DELAY = 1   # 重试间隔（秒）
ENTRY_SNI = 'www.cloudflare.com'
ENTRY_REQUEST = f'HEAD /cdn-cgi/trace HTTP/1.1\r\nHost: {ENTRY_SNI}\r\nConnection: close\r\n\r\n'.encode()
TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE

# —— B 出口能力（OTC 引擎在 CF 内真实 connect）——
CHECK_URL = 'https://api.ytb1.dns-dynamic.net/check?proxyip={addr}'  # 必须走 curl（urllib 403）
CHECK_PARALLEL = 100   # 并发只调这里
CHECK_TIMEOUT = 60
FALLBACK_API = 'https://api.090227.xyz/check'  # 备用（Cmliu，独立引擎）
FALLBACK_TIMEOUT = 30

# —— 地区补全：ipinfo lite ——
REGION_API = 'https://api.ipinfo.io/lite/{ip}?token=2cb674df499388'
REGION_CACHE_FILE = os.path.join(_SCRIPT_DIR, 'Senflare-Country.json')  # 本地缓存：ip → 国家代码
REGION_CACHE_MAX = 10000   # 缓存条数上限
REGION_WORKERS = 32        # 地区查询并发线程数
REGION_TIMEOUT = 5         # 单次查询超时（秒）

OUTPUT_FILE = os.path.join(_SCRIPT_DIR, 'Senflare-Proxy.txt')
ALL_FILE = os.path.join(_SCRIPT_DIR, 'Senflare-Proxy-All.txt')  # 历史采集总库：所有从源采集过的节点,累积去重
INVALID_FILE = os.path.join(_SCRIPT_DIR, 'Senflare-Proxy-Invalid.txt')  # 失败总表：累积所有判定无效的节点
RESCUE_SAMPLE = 500      # 每轮从失败总表随机抽这么多复测
TEST_LIMIT = 0            # 试跑：每源只取前 N 个（0 = 全量）

# ============================================================================
# 六、Cloudflare DNS 自动解析与消息通知配置（优先读取环境变量）
# ============================================================================
CF_DNS_ENABLED = True                                    # 是否开启自动同步到 Cloudflare DNS
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "你的_Zone_ID")  # Cloudflare Zone ID
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "你的_API_Token")  # Cloudflare API Token
CF_DOMAIN_TEMPLATE = "proxyip.{region}.p30.kdns.fr"       # 子域名模板 (已按要求调整为 proxyip.{region}.p30.kdns.fr)
CF_PROXY_STATUS = False                                  # 优选 IP 解析是否开启 Cloudflare 代理小云朵
MAX_RECORDS_PER_REGION = 5                               # 每个指定国家白名单最多同步多少个 IP
MAX_RECORDS_FOR_ALL = 20                                 # all 聚合域名最多同步多少个 IP

# ===== 自建微信推送配置 =====
WECHAT_API_URL = os.environ.get("WECHAT_API_URL", "https://wx.djcf.pp.ua/wxsend")
WECHAT_AUTH_TOKEN = os.environ.get("WECHAT_AUTH_TOKEN", "sb123")
WECHAT_BODY_TEMPLATE = os.environ.get("WECHAT_BODY_TEMPLATE", '{"title":"Proxyip 优选","content":"$MSG"}')

# ===== Telegram 推送配置 =====
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")  # 优先从环境变量读取
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")      # 优先从环境变量读取
TG_API_URL = "https://api.telegram.org/bot"        # TG API地址


# ============================================================================
# 二、拉取与解析（格式解析函数在 SourceParse.py 模块）
# ============================================================================

CF_NETWORKS = [ipaddress.ip_network(n) for n in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', 
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
)]

def is_cf_ip(host):
    """主机是否在 Cloudflare 官方网段内"""
    try:
        addr = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        return False
    return any(addr in net for net in CF_NETWORKS)

def fmt(n):
    """数字千分位格式化，日志更易读"""
    return f'{n:,}'


def node_addr(line):
    """任意节点行(可带地区与标签)→ ip:port；无 # 时整行即地址"""
    base = line.split(' [')[0].strip()
    head, sep, _ = base.rpartition('#')
    return (head if sep else base).strip()

def fetch_text(url, timeout=FETCH_TIMEOUT):
    """拉取数据源文本"""
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', 'ignore')


def load_nodes():
    """拉取两组源 → 去重（待测跳过免测已有）→ (direct, test)；免测组直入主产物"""
    def fetch_group(sources, seen=None):
        seen = seen if seen is not None else set()
        nodes = []
        for name, source in sources.items():
            text = None
            urls = [u for u in (source.get('url'), source.get('fallbackUrl')) if u]
            for url in urls:
                for attempt in range(1, FETCH_RETRIES + 1):
                    try:
                        text = fetch_text(url)
                        break
                    except Exception as e:
                        if attempt < FETCH_RETRIES:
                            print(f'⚠️  [{name}] 第 {attempt} 次拉取失败：{e}，{FETCH_RETRY_DELAY}s 后重试...')
                            time.sleep(FETCH_RETRY_DELAY)
                if text is not None:
                    break
            if text is None:
                print(f'❌ [{name}] 主源+备用共 {len(urls) * FETCH_RETRIES} 次拉取均失败，跳过该源')
                continue

            count = 0
            parsed = parse_source(text, source)
            for node in parsed:
                key = node.rpartition('#')[0]
                if key in seen:
                    continue
                seen.add(key)
                nodes.append(node)
                count += 1
            print(f'🌐 [{name}] 新增 {fmt(count)} 个节点')
        return nodes

    direct_nodes = fetch_group(DIRECT_SOURCES)
    test_nodes = fetch_group(TEST_SOURCES, seen={n.rpartition('#')[0] for n in direct_nodes})
    print(f'\n📊 去重后共 {fmt(len(direct_nodes) + len(test_nodes))} 个节点'
          f'（免测直入 {fmt(len(direct_nodes))} · 待判定 {fmt(len(test_nodes))}）')
    return direct_nodes, test_nodes


# ============================================================================
# 三、出口能力探测（OTC 引擎在 CF 内真实 connect）
# ============================================================================

def recv_all(sock):
    """读到对端关闭或超时，返回完整响应"""
    sock.settimeout(ENTRY_TIMEOUT)
    data = b''
    try:
        while len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def probe_entry(addr):
    """A 入口能力：外部 TLS+SNI 拿到 cf-ray 即入口可用"""
    host, _, port = addr.rpartition(':')
    for attempt in range(ENTRY_TRIES):
        try:
            with socket.create_connection((host.strip('[]'), int(port)), timeout=ENTRY_TIMEOUT) as s:
                with TLS_CTX.wrap_socket(s, server_hostname=ENTRY_SNI) as t:
                    t.sendall(ENTRY_REQUEST)
                    if b'cf-ray' in recv_all(t).lower():
                        return True
        except Exception:
            pass
        if attempt < ENTRY_TRIES - 1:
            time.sleep(ENTRY_RETRY_DELAY)
    return False


def probe_entry_all(addrs):
    """并发探测全部节点的入口能力 返回 {addr: 可否作入口}"""
    print(f'\n🚪 ── 入口能力探测 ── {fmt(len(addrs))} 个节点 · 外部 TLS+SNI · 并发 {ENTRY_WORKERS}')
    out = {}
    with ThreadPoolExecutor(ENTRY_WORKERS) as pool:
        for i, (addr, ok) in enumerate(zip(addrs, pool.map(probe_entry, addrs)), 1):
            out[addr] = ok
            if i % ENTRY_WORKERS == 0 or i == len(addrs):
                print(f'\r⏳ 入口探测 {fmt(i)}/{fmt(len(addrs))} · 可作入口 {fmt(sum(out.values()))}   ',
                      end='', flush=True)
    print(f'\n✅ 入口探测完成 · 可作入口 {fmt(sum(out.values()))} / {fmt(len(addrs))}')
    return out


def parse_ms(text):
    """OTC 返回的响应时间（'5ms' / '1.2s'）→ 毫秒；解析不了返回 0"""
    try:
        v = str(text).strip()
        if v.endswith('ms'):
            return float(v[:-2])
        if v.endswith('s'):
            return float(v[:-1]) * 1000
    except (ValueError, TypeError):
        pass
    return 0.0


def check_exit_one(addr):
    """单个节点出口能力 → (有效, 延迟ms, 原因)；OTC 与 Cmliu 同时查，任一判有效即通过"""
    with ThreadPoolExecutor(2) as pool:
        otc_f, cmliu_f = pool.submit(_check_otc, addr), pool.submit(check_fallback, addr)
        otc_res, cmliu_res = otc_f.result(), cmliu_f.result()

    if otc_res[0]:
        return True, otc_res[1], ''
    if cmliu_res and cmliu_res[0]:
        return True, 0.0, ''
    reason = otc_res[2] or (cmliu_res[1] if cmliu_res else '主备均无结果')
    return False, 0.0, reason


def _check_otc(addr):
    """OTC 单节点 → (有效, 延迟ms, 原因)"""
    try:
        raw = subprocess.run(['curl', '-s', '--max-time', str(CHECK_TIMEOUT),
                              CHECK_URL.format(addr=addr)], capture_output=True).stdout
        d = json.loads(raw.decode('utf-8', 'ignore'))
        if isinstance(d, dict):
            if d.get('有效ProxyIP') is True:
                return True, parse_ms(d.get('响应时间')), ''
            return False, 0.0, str(d.get('失败原因', '') or '主接口判无效')
        return False, 0.0, '主接口无有效返回'
    except Exception as e:
        return False, 0.0, f'主接口异常:{type(e).__name__}'


def check_exit_all(addrs):
    """全量出口能力探测 → {addr: (有效, 延迟ms, 原因)}"""
    print(f'\n🧭 ── 出口能力探测 ── {fmt(len(addrs))} 个节点 · OTC 直连单节点 · 并发 {CHECK_PARALLEL}')
    out = {}
    with ThreadPoolExecutor(CHECK_PARALLEL) as pool:
        for i, (addr, res) in enumerate(zip(addrs, pool.map(check_exit_one, addrs)), 1):
            out[addr] = res
            if i % CHECK_PARALLEL == 0 or i == len(addrs):
                print(f'\r⏳ 出口探测 {fmt(i)}/{fmt(len(addrs))} · '
                      f'有效 {fmt(sum(1 for v in out.values() if v[0]))}   ', end='', flush=True)
    print(f'\n✅ 出口探测完成 · 有效 {fmt(sum(1 for v in out.values() if v[0]))} / {fmt(len(addrs))}')
    return out


def check_fallback(addr):
    """Cmliu 备用检测 → (有效, 原因) 或 None"""
    try:
        qs = urlencode({'proxyip': addr})
        req = urllib.request.Request(f'{FALLBACK_API}?{qs}',
                                     headers={'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=FALLBACK_TIMEOUT) as r:
            data = json.loads(r.read().decode('utf-8', 'ignore'))
        if isinstance(data, dict) and isinstance(data.get('success'), bool):
            reason = ''
            if not data['success']:
                probes = data.get('probe_results') or {}
                probe = probes.get('ipv4') or probes.get('ipv6') or {}
                reason = str(probe.get('error', '') or '备用接口未通过')
            return data['success'], reason
    except Exception:
        pass
    return None


# ============================================================================
# 四、地区补全（缓存优先 → 接口查询）
# ============================================================================

def load_region_cache():
    try:
        with open(REGION_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            return OrderedDict((str(k), str(v)) for k, v in data.items())
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f'⚠️  地区缓存读取失败，按空缓存处理：{e}')
    return OrderedDict()


def save_region_cache(cache):
    while len(cache) > REGION_CACHE_MAX:
        cache.popitem(last=False)
    with open(REGION_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=0)


class RegionRateLimited(Exception):
    """ipinfo 限流标记"""

RATE_LIMITED = object()


def query_ipinfo(ip):
    url = REGION_API.format(ip=ip)
    for _ in range(2):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=REGION_TIMEOUT) as resp:
                data = json.loads(resp.read().decode('utf-8', 'ignore'))
            code = data.get('country_code') or data.get('country') or ''
            return code.upper() if isinstance(code, str) and len(code) == 2 else None
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise RegionRateLimited
            return None
        except Exception:
            continue
    return None


def ensure_regions(nodes):
    cache = load_region_cache()
    result = list(nodes)
    pending_idx = []
    hits = 0
    for i, node in enumerate(result):
        base, _, region = node.rpartition('#')
        if region:
            continue
        host = base.rpartition(':')[0]
        code = cache.get(host)
        if code:
            cache.move_to_end(host)
            hits += 1
            result[i] = f'{base}#{code}'
        else:
            pending_idx.append(i)

    queried_ok = failed = limited = 0
    if pending_idx:
        total = len(pending_idx)
        done = 0
        print(f'\n🌍 ── 地区补全 ── 待查 {fmt(total)} 个 · 缓存命中 {fmt(hits)} · '
              f'ipinfo lite · 并发 {REGION_WORKERS}')

        def work(i):
            host = result[i].rpartition('#')[0].rpartition(':')[0]
            try:
                return i, query_ipinfo(host)
            except RegionRateLimited:
                return i, RATE_LIMITED

        with ThreadPoolExecutor(max_workers=REGION_WORKERS) as pool:
            futures = [pool.submit(work, i) for i in pending_idx]
            for fut in as_completed(futures):
                i, code = fut.result()
                done += 1
                if code is RATE_LIMITED:
                    limited += 1
                elif code:
                    queried_ok += 1
                    base = result[i].rpartition('#')[0]
                    host = base.rpartition(':')[0]
                    result[i] = f'{base}#{code}'
                    cache[host] = code
                else:
                    failed += 1
                    result[i] = None
                now = time.time()
                if done % REGION_WORKERS == 0 or done == total:
                    print(f'\r⏳ 地区查询 进度 {fmt(done)}/{fmt(total)} · 成功 {fmt(queried_ok)}   ',
                          end='', flush=True)

    if hits or pending_idx:
        save_region_cache(cache)
    kept = [n for n in result if n]
    print(f'\n✅ 地区补全完成 · 缓存命中 {fmt(hits)} · 接口成功 {fmt(queried_ok)} · '
          f'失败剔除 {fmt(failed)} · 限流保留 {fmt(limited)} · 缓存存量 {fmt(len(cache))}')
    return kept


# ============================================================================
# 五、Cloudflare DNS 自动解析同步与消息通知
# ============================================================================

def sync_to_cloudflare_dns(final_nodes):
    if not CF_DNS_ENABLED or not CF_ZONE_ID or CF_ZONE_ID == "你的_Zone_ID" or not CF_API_TOKEN or CF_API_TOKEN == "你的_API_Token":
        print("⏭️  Cloudflare DNS 自动同步未开启或配置不完整，跳过。")
        return {}

    print("\n☁️  ── 正在同步优选 IP 到 Cloudflare DNS ──")
    
    target_regions = {'jp', 'kr', 'sg', 'us', 'ca'}
    
    region_ips = {}
    all_ips = []

    for node in final_nodes:
        base, _, region = node.rpartition('#')
        if not region:
            continue
        region_lower = region.lower()
        host = base.rpartition(':')[0].strip('[]')
        
        if host not in all_ips:
            all_ips.append(host)
            
        if region_lower in target_regions:
            if region_lower not in region_ips:
                region_ips[region_lower] = []
            if host not in region_ips[region_lower]:
                region_ips[region_lower].append(host)

    region_ips['all'] = all_ips

    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    sync_stats = {}
    for region, ips in region_ips.items():
        if region == 'all':
            subdomain = "all.proxyip.p30.kdns.fr"
        else:
            subdomain = CF_DOMAIN_TEMPLATE.format(region=region)
            
        print(f"👉 正在处理子域名: {subdomain} (共 {len(ips)} 个 IP)...")

        list_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records?name={subdomain}"
        try:
            req = urllib.request.Request(list_url, headers=headers, method='GET')
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                existing_records = result.get('result', [])
        except Exception as e:
            print(f"   ⚠️ 查询现有 DNS 记录失败 [{subdomain}]: {e}")
            continue

        for rec in existing_records:
            rec_id = rec['id']
            del_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{rec_id}"
            try:
                del_req = urllib.request.Request(del_url, headers=headers, method='DELETE')
                urllib.request.urlopen(del_req, timeout=10)
            except Exception:
                pass

        limit_count = MAX_RECORDS_FOR_ALL if region == 'all' else MAX_RECORDS_PER_REGION
        target_ips = ips[:limit_count]
        
        success_count = 0
        for ip in target_ips:
            rec_type = "AAAA" if ":" in ip else "A"
            payload = {
                "type": rec_type,
                "name": subdomain,
                "content": ip,
                "proxied": CF_PROXY_STATUS,
                "comment": "Senflare Auto ProxyIP"
            }
            create_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records"
            try:
                data_bytes = json.dumps(payload).encode('utf-8')
                create_req = urllib.request.Request(create_url, data=data_bytes, headers=headers, method='POST')
                with urllib.request.urlopen(create_req, timeout=10) as resp:
                    res_json = json.loads(resp.read().decode('utf-8'))
                    if res_json.get('success'):
                        success_count += 1
            except Exception:
                pass

        sync_stats[subdomain] = success_count
        print(f"   ✅ {subdomain} 同步完成：成功写入 {success_count}/{len(target_ips)} 个节点 IP")
    
    return sync_stats


def send_wechat_notification(msg):
    if not WECHAT_API_URL:
        return
    try:
        api_url = WECHAT_API_URL
        if WECHAT_AUTH_TOKEN:
            delimiter = '&' if '?' in api_url else '?'
            api_url = f"{api_url}{delimiter}token={WECHAT_AUTH_TOKEN}"

        # 转换为安全纯文本，彻底避开 WAF/Worker 对特殊符号的 403 拦截
        clean_msg = msg.replace('*', '').replace('`', '')

        body_dict = {
            "title": "Proxyip 优选",
            "content": clean_msg
        }
        data_bytes = json.dumps(body_dict, ensure_ascii=False).encode('utf-8')
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate'
        }
        
        req = urllib.request.Request(api_url, data=data_bytes, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10):
            print("📱 微信通知发送成功")
    except Exception as e:
        print(f"⚠️ 微信通知发送失败: {e}")


def send_telegram_notification(msg):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("⏭️ Telegram 通知未配置完整，跳过发送。")
        return
    try:
        url = f"{TG_API_URL}{TG_BOT_TOKEN}/sendMessage"
        payload = {
            'chat_id': TG_CHAT_ID,
            'text': msg,
            'parse_mode': 'Markdown'
        }
        data_bytes = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10):
            print("✈️ Telegram 通知发送成功")
    except Exception as e:
        print(f"⚠️ Telegram 通知发送失败: {e}")


def send_notifications(summary_text):
    send_wechat_notification(summary_text)
    send_telegram_notification(summary_text)


# ============================================================================
# 六、输出
# ============================================================================

def load_dead_list(lines=None):
    """读失败总表 → {addr: line}"""
    if lines is None:
        lines = [l.strip() for l in open(INVALID_FILE, encoding='utf-8')] if os.path.exists(INVALID_FILE) else []
    latest = {}
    for l in lines:
        if l:
            latest.setdefault(node_addr(l), l)
    return latest


def write_class_files(probed, dead):
    """A×B 四格落盘"""
    groups = {t: [] for t in ('Bidirectional', 'Forward', 'Reverse', 'Invalid')}
    cnt = Counter()
    for node, a_ok, b_ok, _lat, _reason in probed:
        tag = ('Bidirectional' if a_ok and b_ok else 'Forward' if a_ok
               else 'Reverse' if b_ok else 'Invalid')
        cnt[tag] += 1
        groups[tag].append(node)
    rescued = {node_addr(r[0]) for r in probed if r[1] or r[2]} & set(dead)
    if rescued:
        print(f'♻️ 复活 {fmt(len(rescued))} 个（抽样复测通过，从失败总表移除）')
    tested = {node_addr(r[0]) for r in probed}
    groups['Invalid'] += [l for a, l in dead.items() if a not in tested]
    for t, nodes in groups.items():
        nodes.sort(key=lambda l: (l.rpartition('#')[2], l))
        with open(os.path.join(_SCRIPT_DIR, f'Senflare-Proxy-{t}.txt'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(nodes) + '\n' if nodes else '')
    return cnt, len(groups['Invalid'])


def update_all_file(nodes):
    """历史采集总库：本轮采集的全部节点累积进去"""
    merged = {}
    if os.path.exists(ALL_FILE):
        for l in open(ALL_FILE, encoding='utf-8'):
            l = l.strip()
            if l:
                merged.setdefault(node_addr(l), l)
    for n in nodes:
        merged.setdefault(node_addr(n), n)
    with open(ALL_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(merged.values(), key=lambda l: (l.rpartition('#')[2], l))) + '\n')
    return len(nodes), len(merged)


def main():
    started = time.time()
    print('🚀 Senflare Proxy Test 启动')
    if TEST_LIMIT > 0:
        print(f'\n🧪 试跑模式：每个源只取前 {fmt(TEST_LIMIT)} 个节点\n')

    direct_nodes, test_nodes = load_nodes()

    # 剔除 Cloudflare 官方网段
    before = len(direct_nodes) + len(test_nodes)
    direct_nodes = [n for n in direct_nodes if not is_cf_ip(n.rpartition('#')[0].rpartition(':')[0])]
    test_nodes = [n for n in test_nodes if not is_cf_ip(n.rpartition('#')[0].rpartition(':')[0])]
    if before - len(direct_nodes) - len(test_nodes):
        print(f'🧹 Cloudflare 官方网段剔除 {fmt(before - len(direct_nodes) - len(test_nodes))} 个节点')

    if TEST_LIMIT > 0:
        direct_nodes = direct_nodes[:TEST_LIMIT * len(DIRECT_SOURCES)]
        test_nodes = test_nodes[:TEST_LIMIT * len(TEST_SOURCES)]

    # 历史采集总库
    all_new, all_total = update_all_file(direct_nodes + test_nodes)

    dead = load_dead_list()
    rescue = random.sample(sorted(dead), min(RESCUE_SAMPLE, len(dead))) if dead else []
    if rescue:
        print(f'🎲 失败总表抽 {fmt(len(rescue))}/{fmt(len(dead))} 个复测')
    rescue_lines = {a: dead[a] for a in rescue}
    todo = [n for n in test_nodes if node_addr(n) not in dead] + list(rescue_lines.values())
    skipped = len(test_nodes) - sum(1 for n in test_nodes if node_addr(n) not in dead)
    if skipped:
        print(f'⏭️ 死单跳过 {fmt(skipped)} 个')
    addrs = [node_addr(n) for n in todo]
    a_verdict = probe_entry_all(addrs)
    b_verdict = check_exit_all(addrs)
    probed = [(n, a_verdict[node_addr(n)], b_verdict[node_addr(n)][0],
               b_verdict[node_addr(n)][1], b_verdict[node_addr(n)][2]) for n in todo]
    cnt, dead_total = write_class_files(probed, dead)

    tested = sorted((r[0] for r in probed if r[1] or r[2]),
                    key=lambda n: b_verdict[node_addr(n)][1] or float('inf'))
    final_nodes = ensure_regions(direct_nodes + tested)
    if not final_nodes:
        print('❌ 没有任何可用节点，退出')
        sys.exit(1)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_nodes) + '\n')

    print(f'\n💾 已写入 {OUTPUT_FILE}：免测直入 {fmt(len(direct_nodes))} + '
          f'待测可用 {fmt(len(tested))} = 合并 {fmt(len(final_nodes))} 个')
    print(f'🧭 四格分类:双向 {fmt(cnt["Bidirectional"])} · 正向(仅入口) {fmt(cnt["Forward"])} · '
          f'反向(仅出口) {fmt(cnt["Reverse"])} · 无效 {fmt(cnt["Invalid"])} · '
          f'Invalid 在册 {fmt(dead_total)}')
    print(f'📚 采集总库:本轮 {fmt(all_new)} · 累计 {fmt(all_total)} → {ALL_FILE}')

    # 自动同步 DNS
    sync_stats = sync_to_cloudflare_dns(final_nodes)

    elapsed = time.time() - started

    # 组装通知消息
    notif_msg = (
        f"🌐 S Proxy IP 优选完成\n\n"
        f"📊 统计数据：\n"
        f"• 免测直入：{len(direct_nodes)} 个\n"
        f"• 待测可用：{len(tested)} 个\n"
        f"• 最终合并：{len(final_nodes)} 个\n"
        f"⏱️ 总耗时：{elapsed:.0f} 秒\n"
    )
    if sync_stats:
        notif_msg += f"\n☁️ DNS 子域名解析同步：\n"
        for sub, count in sync_stats.items():
            notif_msg += f"• {sub}: 写入 {count} 个IP\n"
    else:
        notif_msg += f"\n☁️ DNS 同步：未开启或未执行\n"

    # 发送双渠道通知
    send_notifications(notif_msg)

    print(f'\n🎉 全部完成 · 耗时 {elapsed:.0f} 秒')


if __name__ == '__main__':
    assert load_dead_list(['1.1.1.1:443#US', '1.1.1.1:443#US', '2.2.2.2:443#US']) == \
        {'1.1.1.1:443': '1.1.1.1:443#US', '2.2.2.2:443': '2.2.2.2:443#US'}, '总表去重错'
    assert (parse_ms('5ms'), parse_ms('1.2s'), parse_ms('x')) == (5.0, 1200.0, 0.0)
    cases = [('a:1#US', True, True), ('b:1#US', True, False),
             ('c:1#US', False, True), ('d:1#US', False, False)]
    tags = ['Bidirectional' if a and b else 'Forward' if a else 'Reverse' if b else 'Invalid'
            for _, a, b in cases]
    assert tags == ['Bidirectional', 'Forward', 'Reverse', 'Invalid'], f'四格映射错: {tags}'
    main()
