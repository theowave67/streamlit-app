#!/usr/bin/env python3
# decrypt_tool.py
# 极简版：无 file 位置参数，所有文件手动指定
# 支持：--encrypt input.json $PASS -o output.sec
#         --env $PASS -o out.json

import os
import sys
import json
import base64
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_to_base64(data: dict, password: str) -> str:
    plaintext = json.dumps(data, ensure_ascii=False).encode('utf-8')
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(salt + nonce + ct).decode('utf-8')

def decrypt_b64_source(b64_input: str, password: str) -> dict | None:
    try:
        data = base64.b64decode(b64_input)
        if len(data) < 44: return None
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        aes = AESGCM(key)
        plain = aes.decrypt(nonce, ct, None).decode('utf-8')
        return json.loads(plain)
    except:
        return None

def main():
    parser = argparse.ArgumentParser(
        description="加密/解密配置文件（.sec / ENCRYPTED_B64）",
        epilog="""
加密:
  python decrypt_tool.py --encrypt input.json $PASS -o output.sec

解密文件:
  python decrypt_tool.py --input encrypted.sec $PASS -o out.json

解密环境变量:
  ENCRYPTED_B64=xxx python decrypt_tool.py --env $PASS -o out.json

查看加密文件明文:
  ENC_PASSWD=xxx python decrypt_tool.py --input encrypted.sec
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # 互斥组
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", metavar="INPUT_JSON", help="加密明文 JSON")
    group.add_argument("--input", metavar="ENCRYPTED_SEC", help="解密 .sec 文件")
    group.add_argument("--env", action="store_true", help="从 ENCRYPTED_B64 解密")
    password = os.environ.get("ENC_PASSWD")
    parser.add_argument("--password", nargs="?", help="密码（优先 $ENC_PASSWD）")
    parser.add_argument("-o", "--output", help="输出路径（加密打印 Base64，解密保存 JSON）")
    parser.add_argument("--raw", action="store_true", help="解密时输出原始 JSON 字符串")

    args = parser.parse_args()

    # 密码
    password = args.password or os.getenv("ENC_PASSWD", "")
    if not password:
        password = input("密码: ") if sys.stdin.isatty() else ""
    if not password:
        print("[ERROR] 密码不能为空", file=sys.stderr)
        sys.exit(1)

    # ==================== 加密 ====================
    if args.encrypt:
        if not os.path.exists(args.encrypt):
            print(f"[ERROR] 文件不存在: {args.encrypt}", file=sys.stderr)
            sys.exit(1)
        with open(args.encrypt, 'r', encoding='utf-8') as f:
            data = json.load(f)
        b64_str = encrypt_to_base64(data, password)

        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(b64_str + '\n')
            print(f"[OK] 加密 → {args.output}")
        else:
            print(b64_str)
        return

    # ==================== 解密 ====================
    if args.env:
        b64_data = os.getenv("ENCRYPTED_B64", "").strip()
        if not b64_data:
            print("[ERROR] ENCRYPTED_B64 未设置", file=sys.stderr)
            sys.exit(1)
        source = "ENCRYPTED_B64"
    else:  # --input
        if not os.path.exists(args.input):
            print(f"[ERROR] 文件不存在: {args.input}", file=sys.stderr)
            sys.exit(1)
        with open(args.input, 'r', encoding='utf-8') as f:
            b64_data = f.read().strip()
        source = args.input

    config = decrypt_b64_source(b64_data, password)
    if not config:
        print(f"[ERROR] 解密失败（{source}）", file=sys.stderr)
        sys.exit(1)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False) if not args.raw else f.write(json.dumps(config))
        print(f"[OK] 解密 → {args.output}")
    else:
        print(json.dumps(config, indent=2, ensure_ascii=False) if not args.raw else json.dumps(config))

if __name__ == "__main__":
    main()
