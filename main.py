import requests, os, sys, base64, json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher

def end(msg, succ=False):
    print(msg)
    with open("result.json", "w") as f:
        f.write(json.dumps({
            "success": succ,
            "message": msg,
        }))
    sys.exit(1 if not succ else 0)

def encrypt(pubkey, msg):
    cipher = PKCS1_cipher.new(pubkey)
    return base64.b64encode(cipher.encrypt(msg)).decode("utf-8")

def decrypt(prikey, msg):
    cipher = PKCS1_cipher.new(prikey)
    return cipher.decrypt(base64.b64decode(msg.encode("utf-8")), None)

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
username = os.environ.get("PKU_USERNAME", None)
password = os.environ.get("PKU_PASSWORD", None)

if not all([username, password]):
    end("Please set PKU_USERNAME and PKU_PASSWORD in environment variables.")

try:
    resp = requests.post("https://treehole.pku.edu.cn/api/login", json={
        "uid": username,
        "password": password,
    }, headers={
        "User-Agent": user_agent,
        "Referer": "https://treehole.pku.edu.cn/web/login",
    })
except:
    end("Failed to connect to server")

try:
    jwt = resp.json().get("data", {}).get("jwt", None)
except:
    end("Failed to parse response")

if not jwt:
    end("Failed to login")

pubkey = RSA.importKey(open("public_key.pem").read())

encrypted = encrypt(pubkey, jwt.encode("utf-8"))

end(encrypted, succ=True)
