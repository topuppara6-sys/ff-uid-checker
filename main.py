import asyncio
import time
import httpx
import json
import logging
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Logging Setup (টার্মিনালে বিস্তারিত দেখার জন্য) ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# শুধুমাত্র বিডি সার্ভারে কাজ করার জন্য
SUPPORTED_REGIONS = {"BD"}


# =====================================================================
# === একাধিক গেস্ট অ্যাকাউন্ট যুক্ত করার তালিকা (GUEST ACCOUNTS LIST) ===
# =====================================================================
# এখানে আপনি ৪-৫টি বা তার বেশি অ্যাকাউন্ট রাখতে পারবেন। ১টি ব্যান হলে পরেরটি দিয়ে কাজ করবে।
# নতুন কোনো অ্যাকাউন্ট যোগ করতে চাইলে ডাবল কোটেশনের (" ") ভেতর নতুন UID ও Password বসাবেন।
GUEST_ACCOUNTS = [
    {
        "uid": "",
        "password": ""
    }
]
# =====================================================================


# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data=payload, headers=headers, timeout=10.0)
            if resp.status_code != 200:
                logging.error(f"Garena OAuth API returned HTTP {resp.status_code}")
                return "0", "0"
            data = resp.json()
            return data.get("access_token", "0"), data.get("open_id", "0")
    except Exception as e:
        logging.error(f"Failed to connect to Garena OAuth: {e}")
        return "0", "0"

async def create_jwt(region: str):
    last_error = "No sychronized guest accounts found."
    
    # তালিকায় থাকা প্রতিটি গেস্ট অ্যাকাউন্ট লুপ করে ট্রাই করবে
    for index, acc in enumerate(GUEST_ACCOUNTS):
        # যদি ইউআইডি বা পাসওয়ার্ড খালি থাকে তবে সেটি স্কিপ করবে
        if not acc["uid"] or not acc["password"]:
            continue
            
        try:
            logging.info(f"[{region}] Attempting token generation with Guest Index {index+1} (UID: {acc['uid']})...")
            
            account_payload = f"uid={acc['uid']}&password={acc['password']}"
            token_val, open_id = await get_access_token(account_payload)
            
            if token_val == "0" or open_id == "0":
                raise Exception("Garena OAuth token generation failed (Account might be banned/expired).")

            body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
            proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
            payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
            
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                       'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
                       'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
            
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, data=payload, headers=headers, timeout=10.0)
                if resp.status_code != 200:
                    raise Exception(f"MajorLogin server returned HTTP {resp.status_code}")
                
                try:
                    msg_proto = decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
                    msg = json.loads(json_format.MessageToJson(msg_proto))
                except Exception as proto_err:
                    raise Exception(f"Protobuf decode failed: {proto_err}")

                token = msg.get('token')
                if not token or token == '0':
                    raise Exception(f"MajorLogin response does not contain a valid token. QueueInfo might be triggered: {msg}")

                # সফলভাবে টোকেন পাওয়া গেলে ক্যাশে সেভ করবে এবং লুপ থেকে বের হয়ে যাবে
                cached_tokens[region] = {
                    'token': f"Bearer {token}",
                    'region': msg.get('lockRegion','0'),
                    'server_url': msg.get('serverUrl','0'),
                    'expires_at': time.time() + 25200
                }
                logging.info(f"[{region}] Token successfully generated using Guest Index {index+1}.")
                return # সাকসেস! ফাংশন থেকে বের হয়ে যাবে।
                
        except Exception as e:
            logging.warning(f"[{region}] Guest Index {index+1} (UID: {acc['uid']}) failed: {e}")
            last_error = str(e)

    # যদি তালিকার কোনো অ্যাকাউন্টই কাজ না করে
    logging.error(f"[{region}] All guest accounts failed to generate a token.")
    cached_tokens[region] = {
        'error': f"All configured guest accounts failed. Last Error: {last_error}",
        'expires_at': time.time() + 300  # ৫ মিনিট পর আবার ট্রাই করবে
    }

# === Token Management Functions ===
async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and 'error' in info and time.time() < info['expires_at']:
        raise Exception(f"Previous token generation failed: {info['error']}")
    if info and 'token' in info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    await create_jwt(region)
    info = cached_tokens.get(region)
    if not info or 'token' not in info:
        err_msg = info.get('error', 'Unknown Error') if info else 'No info cached'
        raise Exception(f"Failed to obtain valid token: {err_msg}")
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    token, lock, server = await get_token_info(region)
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
               
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers, timeout=10.0)
        if resp.status_code != 200:
            raise Exception(f"Player-Info API returned HTTP {resp.status_code}")
        
        try:
            decoded = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            return json.loads(json_format.MessageToJson(decoded))
        except Exception as e:
            raise Exception(f"Failed to decode Player Protobuf response (Keys or Protobuf might be outdated): {e}")

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/player-info', strict_slashes=False)
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    diagnostics = {}
    region = "BD"
    
    try:
        logging.info(f"Searching UID {uid} in region: {region}...")
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        
        if return_data and len(return_data) > 0:
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        else:
            diagnostics[region] = "Empty response (UID not found)"
    except Exception as e:
        logging.warning(f"Region [{region}] check failed for UID {uid}: {e}")
        diagnostics[region] = f"Error: {e}"

    return jsonify({
        "error": "UID not found on BD Server.",
        "diagnostics": diagnostics
    }), 404

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for BD region.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Startup ===
async def startup():
    logging.info("Initializing tokens for BD region...")
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=False)