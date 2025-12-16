#!/usr/bin/env python3

import streamlit as st
import os
import sys
import json
import base64
import time
import re
import subprocess
import requests
import platform
import logging
import threading
import random
import string
from queue import Queue, Empty
from typing import Optional

# ==================== 加密库 ====================
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("请安装: pip install cryptography")
    # 不强制退出，因为可能只使用环境变量

# ==================== 解密函数 ====================
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))

def decrypt_b64_source(b64_input: str, password: str):
    try:
        data = base64.b64decode(b64_input)
        if len(data) < 44:
            return None
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        aes = AESGCM(key)
        plain = aes.decrypt(nonce, ct, None).decode('utf-8')
        return json.loads(plain)
    except:
        print("解密失败")
        return None

def load_config_from_file(file_path: str, password: str):
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r', encoding='utf-8') as f:
        b64_data = f.read().strip()
    return decrypt_b64_source(b64_data, password)

# ==================== 默认配置 ====================
DEFAULT_CONFIG = {
    'UPLOAD_URL': '',
    'PROJECT_URL': '',
    'AUTO_ACCESS': False,
    'FILE_PATH': '/tmp/.cache',
    'SUB_PATH': 'sub',
    'UUID': '1f6f5a40-80d0-4dbf-974d-4d53ff18d639',
    'ARGO_DOMAIN': '',
    'ARGO_AUTH': '',
    'ARGO_PORT': 8001,
    'CFIP': '194.53.53.7',
    'CFPORT': 443,
    'NAME': '',
    'AUTH_ACCESS': '',
    'NEZHA_SERVER': '',
    'NEZHA_PORT': '',
    'NEZHA_KEY': '',
    'DDDEBUG': False
}

# ==================== 加载配置 ====================
def load_config():
    # 1. 尝试从环境变量获取密码
    pwd = os.environ.get("ENC_PASSWD", "")
    
    config = None
    B64 = os.getenv('ENCRYPTED_B64', '').strip()
    if B64:
        print("Trying to decrypt ENCRYPTED_B64")
        config = decrypt_b64_source(B64, pwd)
    elif os.environ.get('ENC_DATA_FILE'):
        config = load_config_from_file(os.environ.get('ENC_DATA_FILE'), pwd)
    
    merged = DEFAULT_CONFIG.copy()
    
    # 2. 合并解密配置 (Encrypted Config)
    if config:
        for k, v in config.items():
            uk = k.upper()
            if uk in merged:
                if isinstance(merged[uk], bool):
                    merged[uk] = bool(v)
                elif isinstance(merged[uk], int):
                    merged[uk] = int(v)
                else:
                    merged[uk] = v

    # 3. 环境变量覆盖 (Environment Variables Override) - 兼容旧方式
    env_map = {
        'UPLOAD_URL': 'UPLOAD_URL',
        'PROJECT_URL': 'PROJECT_URL',
        'AUTO_ACCESS': 'AUTO_ACCESS',
        'FILE_PATH': 'FILE_PATH',
        'SUB_PATH': 'SUB_PATH',
        'ID': 'UUID',
        'PASSWD': 'AUTH_ACCESS',
        'NEZHA_SERVER': 'NEZHA_SERVER',
        'NEZHA_PORT': 'NEZHA_PORT',
        'NEZHA_KEY': 'NEZHA_KEY',
        'HOST': 'ARGO_DOMAIN',
        'DATA': 'ARGO_AUTH',
        'PORT': 'ARGO_PORT',
        'GOODIP': 'CFIP',
        'GOODPORT': 'CFPORT',
        'NAME': 'NAME',
        'DDDEBUG': 'DDDEBUG'
    }

    for env_key, config_key in env_map.items():
        val = os.environ.get(env_key)
        if val is not None:
             if isinstance(merged[config_key], bool):
                 merged[config_key] = val.lower() in ('true', '1', 'yes')
             elif isinstance(merged[config_key], int):
                 try:
                     merged[config_key] = int(val)
                 except:
                     pass
             else:
                 merged[config_key] = val
                 
    return merged

config_data = load_config()

# ====================== 配置 & 日志 ======================
DDDEBUG = config_data.get('DDDEBUG', False)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG if DDDEBUG else logging.INFO)

if logger.handlers:
    logger.handlers.clear()

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG if DDDEBUG else logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

log = logging.getLogger()  # 快捷别名

# 环境变量 (From Config)
UPLOAD_URL = config_data['UPLOAD_URL']
PROJECT_URL = config_data['PROJECT_URL']
AUTO_ACCESS = config_data['AUTO_ACCESS']
FILE_PATH = config_data['FILE_PATH']
SUB_PATH = config_data['SUB_PATH']
UUID = config_data['UUID']
PASSWD = config_data['AUTH_ACCESS']
NEZHA_SERVER = config_data['NEZHA_SERVER']
NEZHA_PORT = config_data['NEZHA_PORT']
NEZHA_KEY = config_data['NEZHA_KEY']
ARGO_DOMAIN = config_data['ARGO_DOMAIN']
ARGO_AUTH = config_data['ARGO_AUTH']
ARGO_PORT = int(config_data['ARGO_PORT'])
CFIP = config_data['CFIP']
CFPORT = int(config_data['CFPORT'])
NAME = config_data['NAME']

os.makedirs(FILE_PATH, exist_ok=True)

# 路径
subPath = os.path.join(FILE_PATH, 'sub.txt')
bootLogPath = os.path.join(FILE_PATH, 'boot.log')
configPath = os.path.join(FILE_PATH, 'config.json')
npmPath = os.path.join(FILE_PATH, 'npm')
phpPath = os.path.join(FILE_PATH, 'php')
lockFile = os.path.join(FILE_PATH, 'service.lock')  # 永久保留

log.debug(f"Configuration loaded | DDDEBUG={'ON' if DDDEBUG else 'OFF'}")
log.debug(f"FILE_PATH={FILE_PATH} | lockFile={lockFile}")


# ====================== 工具函数 ======================
def generate_random_name(length=5):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def check_passwd(user_input: str) -> bool:
    return user_input.strip() == PASSWD.strip()


def run_subprocess_with_output(cmd: list, name: str, cwd: Optional[str] = None):
    """
    启动子进程，DDDEBUG=True 时实时打印 stdout/stderr
    """
    if not DDDEBUG:
        # 静默运行
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cwd)

    log.debug(f"[{name}] Starting: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=cwd
    )

    def stream_output(stream, prefix):
        queue = Queue()
        def enqueue():
            for line in iter(stream.readline, ''):
                queue.put(line)
            queue.put(None)
        t = threading.Thread(target=enqueue, daemon=True)
        t.start()

        while True:
            try:
                line = queue.get(timeout=0.1)
                if line is None:
                    break
                line = line.strip()
                if line:
                    log.debug(f"[{name} {prefix}] {line}")
            except Empty:
                if process.poll() is not None:
                    break
                continue

    # 启动两个线程分别读取 stdout 和 stderr
    threading.Thread(target=stream_output, args=(process.stdout, "OUT"), daemon=True).start()
    threading.Thread(target=stream_output, args=(process.stderr, "ERR"), daemon=True).start()

    # 等待进程启动完成
    time.sleep(0.5)
    if process.poll() is not None:
        rc = process.returncode
        log.error(f"[{name}] Process exited immediately with code {rc}")
        raise RuntimeError(f"{name} failed to start")

    log.debug(f"[{name}] Process started successfully | PID={process.pid}")
    return process


def get_isp():
    def get_isp_from_ip_api():
        try:
            url = 'http://ip-api.com/json/'
            resp = requests.get(url, timeout=10)
            print(f"ip-api meta: {resp.text}")
            meta = resp.json()
            country = meta.get('countryCode', None)
            ip = meta.get('query', None)
            ISP = f"{country}-{ip}"
        except Exception as err:
            print(f"Get ISP info error: {err}")
            ISP = None
        return ISP

    def get_isp_from_ipapi():
        try:
            url = "https://api.ipapi.is"
            resp = requests.get(url, timeout=10)
            print(f"ipapi meta: {resp.text}")
            meta = resp.json()
            ip = meta.get('ip', '')
            country = meta.get('location', {}).get('country_code', None)
            ISP = f"{country}-{ip}"
        except Exception as err:
            print(f"Get ISP info error: {err}")
            ISP = None
        return ISP
    
    ISP = get_isp_from_ip_api()
    if not ISP:
        ISP = get_isp_from_ipapi()
    if ISP is None:
        ISP = 'Unknown'
    ISP = ISP.replace(' ', '-')
    return ISP


# ====================== 永久内存缓存订阅 =======================
@st.cache_data(show_spinner=False)
def get_global_subscription(_domain: str) -> str:
    ISP = get_isp()
    raw = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={_domain}&fp=chrome&type=ws&host={_domain}&path=%2Fvless-argo%3Fed%3D2560#{NAME}-{ISP}"""
    b64_content = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
    log.debug(f"Generated base64 subscription | length={len(b64_content)}")

    # 临时写入 sub.txt（仅用于上传）
    try:
        with open(subPath, 'w', encoding='utf-8') as f:
            f.write(b64_content)
        log.debug(f"Subscription written to: {subPath}")
        if UPLOAD_URL and PROJECT_URL:
            try:
                upload_payload = {"subscription": [f"{PROJECT_URL}/{SUB_PATH}"]}
                log.debug(f"Uploading subscription URL: {upload_payload}")
                requests.post(
                    f"{UPLOAD_URL}/api/add-subscriptions",
                    json=upload_payload,
                    timeout=10
                )
                log.debug("Subscription URL uploaded successfully")
            except Exception as e:
                log.warning(f"Upload failed: {e}")
    except Exception as e:
        log.warning(f"Failed to write sub.txt: {e}")

    return b64_content


# ====================== 全局服务启动（只看 lockFile）======================
@st.cache_resource(show_spinner="Starting global proxy service...")
def start_proxy_service_once():
    if os.path.exists(lockFile):
        log.info("Service already initialized (lockFile exists)")
        domain = ARGO_DOMAIN
        if not domain and os.path.exists(bootLogPath):
            try:
                with open(bootLogPath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if m := re.search(r'https?://([^ ]*trycloudflare\.com)', content):
                        domain = m.group(1)
                        log.debug(f"Extracted domain from boot.log: {domain}")
            except Exception as e:
                log.debug(f"Failed to read boot.log: {e}")
        return domain or "unknown.trycloudflare.com"

    log.debug("Starting global proxy service initialization...")
    web_file_name = generate_random_name(5)
    bot_file_name = generate_random_name(5)
    webPath = os.path.join(FILE_PATH, web_file_name)
    botPath = os.path.join(FILE_PATH, bot_file_name)

    log.debug(f"Generated file names: web={web_file_name}, bot={bot_file_name}")
    log.debug(f"Web path: {webPath}, Bot path: {botPath}")

    # 1. 生成 xray 配置
    log.debug("Generating xray configuration...")
    config = {
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
        "inbounds": [
            {
                "port": ARGO_PORT, "protocol": "vless",
                "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none",
                             "fallbacks": [{"dest": 3001}, {"path": "/vless-argo", "dest": 3002}]},
                "streamSettings": {"network": "tcp"}
            },
            {"port": 3001, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "none"}},
            {"port": 3002, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": [{"id": UUID, "level": 0}], "decryption": "none"},
             "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless-argo"}},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}},
        ],
        "dns": {"servers": ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"]},
        "routing": {"rules": [{"type": "field", "domain": ["v.com"], "outboundTag": "force-to-ip"}]},
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
            {"tag": "force-to-ip", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:0"}}
        ]
    }
    try:
        with open(configPath, 'w') as f:
            json.dump(config, f, indent=2)
        log.debug(f"Xray config written to: {configPath}")
    except Exception as e:
        log.error(f"Failed to write config.json: {e}")
        raise

    # 2. 下载文件
    arch = 'arm' if 'arm' in platform.machine().lower() or 'aarch64' in platform.machine().lower() else 'amd'
    log.info(f"Detected architecture: {arch}64")
    files = [
        {"fileName": web_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/web"},
        {"fileName": bot_file_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/2go"}
    ]

    if NEZHA_SERVER and NEZHA_KEY:
        agent = "agent" if NEZHA_PORT else "v1"
        agent_name = "npm" if NEZHA_PORT else "php"
        agent_path = os.path.join(FILE_PATH, agent_name)
        if agent_name == "npm":
            globals()['npmPath'] = agent_path
        else:
            globals()['phpPath'] = agent_path
        files.insert(0, {"fileName": agent_name, "fileUrl": f"https://{arch}64.ssss.nyc.mn/{agent}"})
        log.debug(f"Adding Nezha agent: {agent_name} -> {agent_path}")

    for f in files:
        path = os.path.join(FILE_PATH, f['fileName'])
        log.debug(f"Downloading {f['fileName']} from {f['fileUrl']}")
        try:
            r = requests.get(f['fileUrl'], stream=True, timeout=15)
            r.raise_for_status()
            with open(path, 'wb') as wf:
                for c in r.iter_content(8192):
                    wf.write(c)
            os.chmod(path, 0o775)
            log.debug(f"Downloaded and chmod 775: {path}")
        except Exception as e:
            log.error(f"Failed to download {f['fileName']}: {e}")
            raise

    # 3. 启动 xray
    log.info("Starting web...")
    xray_cmd = [webPath, '-c', configPath]
    try:
        run_subprocess_with_output(xray_cmd, "XRAY")
        time.sleep(5)
        log.debug("xray started, waiting 5s for stabilization")
    except Exception as e:
        log.error(f"Failed to start xray: {e}")
        raise

    # 4. 启动 cloudflared
    log.info("Starting cfd...")
    cfd_cmd = [botPath]
    if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH]
        log.debug("Using Argo token mode")
    elif 'TunnelSecret' in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        try:
            tunnel_id = json.loads(ARGO_AUTH).get("TunnelID") or ARGO_AUTH.split('"')[11]
        except:
            tunnel_id = "unknown"
        yaml_content = f"""tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2
ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(yaml_content)
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--config", os.path.join(FILE_PATH, 'tunnel.yml'), "run"]
        log.debug("Using Argo config file mode")
    else:
        cfd_cmd += ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
                    "--logfile", bootLogPath, "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"]
        log.debug("Using ephemeral tunnel mode (trycloudflare)")

    log.debug(f"cloudflared command: {' '.join(cfd_cmd)}")
    try:
        run_subprocess_with_output(cfd_cmd, "CLOUDFLARED")
        time.sleep(3)
    except Exception as e:
        log.error(f"Failed to start cloudflared: {e}")
        raise

    # 5. 提取域名
    domain = ARGO_DOMAIN or _extract_argo_domain_from_log()
    log.debug(f"Argo domain resolved: {domain}")

    # 6. 生成订阅
    log.debug("Generating subscription links...")
    get_global_subscription(domain)

    # 7. 创建 lockFile
    try:
        with open(lockFile, 'w') as f:
            f.write(str(int(time.time())))
        log.info("lockFile created - service permanently initialized")
    except Exception as e:
        log.error(f"Failed to create lockFile: {e}")
        raise

    # 8. 访问任务
    if AUTO_ACCESS and PROJECT_URL:
        try:
            requests.post('https://oooo.serv00.net/add-url', json={"url": PROJECT_URL}, timeout=5)
            log.debug("AUTO_ACCESS URL submitted")
        except Exception as e:
            log.debug(f"AUTO_ACCESS failed: {e}")

    log.info("GLOBAL SERVICE INITIALIZED SUCCESSFULLY")
    return domain


def _extract_argo_domain_from_log():
    log.debug("Attempting to extract Argo domain from boot.log")
    for i in range(15):
        if os.path.exists(bootLogPath):
            try:
                with open(bootLogPath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if m := re.search(r'https?://([^ ]*trycloudflare\.com)', content):
                        domain = m.group(1)
                        log.debug(f"Domain found in log (attempt {i+1}): {domain}")
                        return domain
                    else:
                        log.debug(f"No domain found in log (attempt {i+1})")
            except Exception as e:
                log.debug(f"Error reading boot.log (attempt {i+1}): {e}")
        else:
            log.debug(f"boot.log not exists yet (attempt {i+1}), waiting...")
        time.sleep(2)
    log.warning("Failed to extract domain after 15 attempts")
    return "unknown.trycloudflare.com"


# ====================== 自动清理（90秒后，**不删 lockFile**）======================
def schedule_cleanup():
    def _cleanup():
        time.sleep(90)
        files = [bootLogPath, configPath, subPath]
        for path in [globals().get('webPath'), globals().get('botPath'), npmPath, phpPath]:
            if path and os.path.exists(path):
                files.append(path)
        for ext in ['tunnel.json', 'tunnel.yml']:
            f = os.path.join(FILE_PATH, ext)
            if os.path.exists(f):
                files.append(f)
        if files:
            cmd = f"rm -f {' '.join(files)}"
            log.debug(f"Cleaning up temporary files: {cmd}")
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.debug(f"Temporary files cleaned ({len(files)} files), lockFile kept")
    threading.Thread(target=_cleanup, daemon=True).start()


# ====================== 主界面 ======================
def main():
    st.set_page_config(page_title="Viewer", layout="centered")
    st.title("Viewer")
    st.markdown("---")

    if "passwd_verified" not in st.session_state:
        st.session_state.passwd_verified = False
    if "argo_domain" not in st.session_state:
        st.session_state.argo_domain = None

    if not os.path.exists(lockFile):
        with st.spinner("Initializing global service (first user triggers)..."):
            try:
                domain = start_proxy_service_once()
                st.session_state.argo_domain = domain
                schedule_cleanup()
                st.success("Service initialized!")
                st.info("Refresh and enter password")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Init failed: {e}")
                log.error(f"Service initialization error: {e}", exc_info=True)
        return
    else:
        if st.session_state.argo_domain is None:
            domain = ARGO_DOMAIN
            if not domain and os.path.exists(bootLogPath):
                try:
                    with open(bootLogPath, 'r') as f:
                        if m := re.search(r'https?://([^ ]*trycloudflare\.com)', f.read()):
                            domain = m.group(1)
                            log.debug(f"Domain from boot.log in UI: {domain}")
                except Exception as e:
                    log.debug(f"UI boot.log read failed: {e}")
            st.session_state.argo_domain = domain or "unknown.trycloudflare.com"

    if not st.session_state.passwd_verified:
        pwd = st.text_input("Enter password", type="password", placeholder="Default: admin123")
        if pwd:
            if check_passwd(pwd):
                st.session_state.passwd_verified = True
                st.success("Login successful!")
                log.info("User logged in successfully")
                st.rerun()
            else:
                st.error("Incorrect password")
                log.warning("Login failed: incorrect password")
        else:
            st.info("Please enter the correct password")
        return

    b64_content = get_global_subscription(st.session_state.argo_domain)

    st.subheader("Subscription (Base64)")
    st.text_area("Click to select all", b64_content, height=150)
    st.download_button("Download sub.txt", b64_content, "sub.txt", "text/plain")
    st.success("Done!")

    if st.button("Force Refresh Cache (Admin)"):
        get_global_subscription.clear()
        st.success("Refreshing cache...")
        log.debug("Admin forced subscription cache refresh")
        st.rerun()


if __name__ == "__main__":
    main()
    sys.stdout.flush()