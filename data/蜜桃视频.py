# coding=utf-8
# !/usr/bin/python

import sys
sys.path.append('..')

from base.spider import BaseSpider
import requests
import json
import base64
import hashlib
import time
import re
import string
import random
import threading
from urllib.parse import quote, unquote
import urllib3

# 忽略 SSL 证书警告，防止控制台爆警告日志导致盒子卡死
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

SITES = [
    {'name': 'nht966', 'host': 'https://www.nht966hht.vip:9527'},
    {'name': 'httre666', 'host': 'https://www.newhttestre666.cc'},
]

SIGN_KEY  = 'opum3_Loily$SV^6H'
BUNDLE_ID = 'com.ht9.web20.video'
BRAND_ID  = 'hongtao'
VERSION   = '1.0.0'
PROJECT_ID = '1'

PROXY_TYPE = 'mitao_img'


# =====================================================================
# 纯 Python 实现的 AES-128-CBC 加解密 (不依赖 Crypto 库)
# =====================================================================
class SimpleAES:
    """
    一个轻量级的纯 Python AES 128 CBC 实现，用于避免盒子环境缺少 pycryptodome 库的问题。
    包含基本的字节处理及矩阵变换。
    """
    s_box = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )

    inv_s_box = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    )

    @staticmethod
    def _sub_bytes(state):
        for i in range(4):
            for j in range(4):
                state[i][j] = SimpleAES.s_box[state[i][j]]

    @staticmethod
    def _inv_sub_bytes(state):
        for i in range(4):
            for j in range(4):
                state[i][j] = SimpleAES.inv_s_box[state[i][j]]

    @staticmethod
    def _shift_rows(state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    @staticmethod
    def _inv_shift_rows(state):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

    @staticmethod
    def _xtime(a):
        return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    @staticmethod
    def _mix_single_column(r):
        t = r[0] ^ r[1] ^ r[2] ^ r[3]
        u = r[0]
        r[0] ^= t ^ SimpleAES._xtime(r[0] ^ r[1])
        r[1] ^= t ^ SimpleAES._xtime(r[1] ^ r[2])
        r[2] ^= t ^ SimpleAES._xtime(r[2] ^ r[3])
        r[3] ^= t ^ SimpleAES._xtime(r[3] ^ u)

    @staticmethod
    def _mix_columns(state):
        for i in range(4):
            col = [state[0][i], state[1][i], state[2][i], state[3][i]]
            SimpleAES._mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]

    @staticmethod
    def _inv_mix_columns(state):
        for i in range(4):
            u = SimpleAES._xtime(SimpleAES._xtime(state[0][i] ^ state[2][i]))
            v = SimpleAES._xtime(SimpleAES._xtime(state[1][i] ^ state[3][i]))
            state[0][i] ^= u
            state[1][i] ^= v
            state[2][i] ^= u
            state[3][i] ^= v
        SimpleAES._mix_columns(state)

    @staticmethod
    def _add_round_key(state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]

    @staticmethod
    def _key_expansion(key):
        key_symbols = [b for b in key]
        key_words = []
        for i in range(4):
            key_words.append(key_symbols[4*i:4*i+4])

        for i in range(4, 44):
            temp = list(key_words[i-1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]
                temp = [SimpleAES.s_box[b] for b in temp]
                temp[0] ^= SimpleAES.r_con[i // 4]
            word = []
            for j in range(4):
                word.append(key_words[i-4][j] ^ temp[j])
            key_words.append(word)

        round_keys = []
        for i in range(11):
            round_key = [[0]*4 for _ in range(4)]
            for j in range(4):
                for k in range(4):
                    round_key[k][j] = key_words[i*4 + j][k]
            round_keys.append(round_key)
        return round_keys

    @staticmethod
    def encrypt_block(block, round_keys):
        state = [[0]*4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = block[i*4 + j]

        SimpleAES._add_round_key(state, round_keys[0])

        for i in range(1, 10):
            SimpleAES._sub_bytes(state)
            SimpleAES._shift_rows(state)
            SimpleAES._mix_columns(state)
            SimpleAES._add_round_key(state, round_keys[i])

        SimpleAES._sub_bytes(state)
        SimpleAES._shift_rows(state)
        SimpleAES._add_round_key(state, round_keys[10])

        out = [0]*16
        for i in range(4):
            for j in range(4):
                out[i*4 + j] = state[j][i]
        return bytes(out)

    @staticmethod
    def decrypt_block(block, round_keys):
        state = [[0]*4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = block[i*4 + j]

        SimpleAES._add_round_key(state, round_keys[10])

        for i in range(9, 0, -1):
            SimpleAES._inv_shift_rows(state)
            SimpleAES._inv_sub_bytes(state)
            SimpleAES._add_round_key(state, round_keys[i])
            SimpleAES._inv_mix_columns(state)

        SimpleAES._inv_shift_rows(state)
        SimpleAES._inv_sub_bytes(state)
        SimpleAES._add_round_key(state, round_keys[0])

        out = [0]*16
        for i in range(4):
            for j in range(4):
                out[i*4 + j] = state[j][i]
        return bytes(out)

    @staticmethod
    def encrypt_cbc(plaintext, key, iv):
        round_keys = SimpleAES._key_expansion(key)
        ciphertext = bytearray()
        prev = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            xored = bytes(b1 ^ b2 for b1, b2 in zip(block, prev))
            encrypted = SimpleAES.encrypt_block(xored, round_keys)
            ciphertext.extend(encrypted)
            prev = encrypted
        return bytes(ciphertext)

    @staticmethod
    def decrypt_cbc(ciphertext, key, iv):
        round_keys = SimpleAES._key_expansion(key)
        plaintext = bytearray()
        prev = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted = SimpleAES.decrypt_block(block, round_keys)
            xored = bytes(b1 ^ b2 for b1, b2 in zip(decrypted, prev))
            plaintext.extend(xored)
            prev = block
        return bytes(plaintext)


# =====================================================================
# 爬虫核心逻辑类
# =====================================================================
class Spider(BaseSpider):

    def getName(self):
        return "蜜桃视频"

    def isVideoFormat(self, url):
        return url and ('.mp4' in url or '.m3u8' in url or '.ts' in url)

    def manualVideoCheck(self):
        return False

    filterable = True
    searchable = True
    host = SITES[0]['host']
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "lang": "cn",
        "deviceType": "H5-android",
    }

    # ----------------- 内存级缓存（规避文件I/O崩溃） -----------------
    _mem_speed_cache = {'host': '', 'ts': 0}
    _speed_cache_ttl = 1800
    _lock = threading.Lock()
    _speed_test_done = False
    
    _user_id = ''
    _session_id = ''
    _device_id = ''
    _session_inited = False
    _categories = []
    _video_type_list = []
    
    _mem_session_cache = {'ts': 0, 'data': {}}
    _session_cache_ttl = 1800 

    def _get_cached_site(self):
        age = time.time() - self._mem_speed_cache.get('ts', 0)
        host = self._mem_speed_cache.get('host', '')
        if age < self._speed_cache_ttl and host:
            return host, True
        return '', False

    def _save_cached_site(self, host):
        self._mem_speed_cache['host'] = host
        self._mem_speed_cache['ts'] = time.time()

    def _resolve_host(self, portal):
        try:
            r = requests.get(portal, headers=self.headers, timeout=TIMEOUT,
                             verify=False, allow_redirects=True)
            text = r.text or ''
            if 'targetSites' in text:
                m = re.search(r'targetSites\s*=\s*\[(.*?)\]', text, re.S)
                if m:
                    urls = re.findall(r'https?://[^\s"\',\]]+', m.group(1))
                    if urls:
                        return urls[0].rstrip('/')
                return ''
            if r.status_code == 200:
                return portal.rstrip('/')
        except Exception:
            pass
        return ''

    def _select_best_site(self):
        if self._speed_test_done:
            return
        cached_host, valid = self._get_cached_site()
        if valid:
            self.host = cached_host
            self._speed_test_done = True
            return

        resolved = ''
        for s in SITES:
            h = self._resolve_host(s['host'])
            if h:
                resolved = h
                break

        self.host = resolved or SITES[0]['host']
        self._speed_test_done = True
        if resolved:
            self._save_cached_site(resolved)

    def _save_session_cache(self):
        self._mem_session_cache['ts'] = time.time()
        self._mem_session_cache['data'] = {
            'user_id': self._user_id,
            'session_id': self._session_id,
            'device_id': self._device_id,
            'categories': self._categories,
            'video_type_list': self._video_type_list,
        }

    def _load_session_cache(self):
        age = time.time() - self._mem_session_cache.get('ts', 0)
        if age >= self._session_cache_ttl:
            return False
        data = self._mem_session_cache.get('data', {})
        self._user_id = data.get('user_id', '')
        self._session_id = data.get('session_id', '')
        self._device_id = data.get('device_id', '')
        self._categories = data.get('categories', [])
        self._video_type_list = data.get('video_type_list', [])
        if not self._user_id or not self._session_id:
            return False
        return True

    @staticmethod
    def _zero_pad(data, block_size=16):
        pad_len = block_size - (len(data) % block_size)
        if pad_len == block_size:
            return data
        return data + b'\x00' * pad_len

    @staticmethod
    def _zero_unpad(data):
        return data.rstrip(b'\x00')

    def _gen_key(self, timestamp):
        ts = str(timestamp)
        return ts[-6:] + SIGN_KEY[:4] + BUNDLE_ID[:6]

    def _gen_iv(self):
        return BUNDLE_ID[-6:] + SIGN_KEY[-4:] + self._device_id[:6]

    def _aes_encrypt(self, plaintext, key_str, iv_str):
        key = key_str.encode('utf-8')
        iv = iv_str.encode('utf-8')
        data = plaintext.encode('utf-8')
        padded = self._zero_pad(data)
        encrypted = SimpleAES.encrypt_cbc(padded, key, iv)
        return base64.b64encode(encrypted).decode('utf-8')

    def _aes_decrypt(self, ciphertext_b64, key_str, iv_str):
        key = key_str.encode('utf-8')
        iv = iv_str.encode('utf-8')
        cleaned = re.sub(r'\s', '', ciphertext_b64)
        encrypted = base64.b64decode(cleaned)
        decrypted = SimpleAES.decrypt_cbc(encrypted, key, iv)
        unpadded = self._zero_unpad(decrypted)
        return unpadded.decode('utf-8', errors='replace')

    def _generate_sign(self, params, api_path):
        sorted_keys = sorted(params.keys())
        concat = ''
        for k in sorted_keys:
            concat += str(params[k])
        raw = concat + SIGN_KEY + api_path
        return hashlib.md5(raw.encode('utf-8')).hexdigest().upper()

    @staticmethod
    def _generate_device_id():
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
        return 'H5-' + rand

    def _common_params(self):
        hostname = self.host.replace('https://', '').replace('http://', '')
        return {
            'timezone': 'Asia/Karachi',
            'version': VERSION,
            'channelId': 67,  
            'channelId2': hostname,
            'brandId': BRAND_ID,
        }

    def _api_request(self, endpoint, params=None, skip_encrypt=False, _t=None):
        if params is None:
            params = {}

        timestamp = str(_t) if _t else str(int(time.time() * 1000))
        key_str = self._gen_key(timestamp)
        iv_str = self._gen_iv()

        full_params = self._common_params()
        full_params['t'] = timestamp
        full_params.update(params)

        full_params['sign'] = self._generate_sign(full_params, endpoint)

        api_url = self.host + endpoint
        headers = dict(self.headers)
        headers['t'] = timestamp

        if self._user_id:
            headers['userId'] = self._user_id
        if self._session_id:
            headers['sessionId'] = self._session_id

        headers['deviceId'] = self._device_id or ''
        headers['bundleId'] = BUNDLE_ID

        if skip_encrypt:
            body = json.dumps(full_params, ensure_ascii=False, separators=(',', ':'))
            headers['Content-Type'] = 'application/json'
            headers['encrypt'] = 'false'
        else:
            plain = json.dumps(full_params, ensure_ascii=False, separators=(',', ':'))
            body = self._aes_encrypt(plain, key_str, iv_str)
            headers['Content-Type'] = 'text/plain'
            headers['encrypt'] = 'true'

        try:
            r = self.session.post(api_url, data=body,
                                  headers=headers, timeout=TIMEOUT, verify=False)
            resp = r.json()

            if resp.get('code') == 10000 and isinstance(resp.get('data'), str) and resp['data']:
                try:
                    decrypted = self._aes_decrypt(resp['data'], key_str, iv_str)
                    resp['data'] = json.loads(decrypted)
                except Exception:
                    pass
            return resp
        except Exception:
            return None

    def _ensure_session(self):
        if self._session_inited:
            return
        if self._load_session_cache():
            self._session_inited = True
            if not self._video_type_list:
                appcfg = self._api_request('/ht/users/appConfig')
                if appcfg and appcfg.get('code') == 10000:
                    ac_data = appcfg.get('data', {})
                    if isinstance(ac_data, dict) and ac_data.get('appConfig'):
                        ac_cfg = ac_data['appConfig']
                        if isinstance(ac_cfg, dict) and ac_cfg.get('videoTypeList'):
                            self._video_type_list = ac_cfg['videoTypeList']
            return

        if not self._device_id:
            self._device_id = self._generate_device_id()

        appcfg = self._api_request('/ht/users/appConfig')
        if appcfg and appcfg.get('code') == 10000:
            ac_data = appcfg.get('data', {})
            if isinstance(ac_data, dict) and ac_data.get('appConfig'):
                ac_cfg = ac_data['appConfig']
                if isinstance(ac_cfg, dict) and ac_cfg.get('videoTypeList'):
                    self._video_type_list = ac_cfg['videoTypeList']

        shared_t = int(time.time() * 1000)
        resp1 = self._api_request('/ht/users/initH5_1', _t=shared_t)

        if resp1 and resp1.get('code') == 10000:
            data = resp1.get('data', {})
            if data.get('deviceId'):
                self._device_id = data['deviceId']
            if data.get('typeTitleList'):
                self._categories = data['typeTitleList']

        self._api_request('/ht/users/initH5_2', _t=shared_t)

        resp = self._api_request('/ht/users/deviceLogin', {
            'bundleId': BUNDLE_ID,
            'brandId': BRAND_ID,
            'projectId': PROJECT_ID,
        })
        if resp and resp.get('code') == 10000:
            data = resp.get('data', {})
            self._user_id = data.get('userId', '')
            self._session_id = data.get('sessionId', '')

        self._session_inited = True
        self._save_session_cache()

    def get_proxy_image_url(self, img_url):
        if not img_url:
            return ''
        base_proxy = self.getProxyUrl()
        if not base_proxy:
            base_proxy = 'http://127.0.0.1:9980/proxy?do=py'
        return base_proxy + '&type=' + PROXY_TYPE + '&url=' + quote(img_url, safe='')

    def _fmt_duration(self, seconds):
        try:
            s = int(seconds or 0)
        except (TypeError, ValueError):
            return ''
        if s <= 0:
            return ''
        m, s = divmod(s, 60)
        return f"{m}:{s:02d}"

    def init(self, extend=""):
        cached_host, valid = self._get_cached_site()
        if valid:
            self.host = cached_host
            self._speed_test_done = True

    _CATEGORY_BLACKLIST = {'成人游戏', '漫画', '小说', '蜜穴女友', '一键脱衣', '春药商城', '同城交友', '吃瓜', '成人漫画', '女优', '专题'}

    def homeContent(self, filter):
        self._select_best_site()
        self._ensure_session()

        classes = []
        filters = {}

        for cat in self._categories:
            cid = str(cat.get('contentId', ''))
            title = cat.get('title', '')
            if not cid or not title or title in self._CATEGORY_BLACKLIST:
                continue
            classes.append({'type_id': cid, 'type_name': title})

            cat_filters = []

            sub_cats = [v for v in self._video_type_list if str(v.get('typePid', '')) == cid]
            if sub_cats:
                sub_values = [{'n': '全部', 'v': ''}]
                for sc in sub_cats:
                    sc_id = str(sc.get('typeId', ''))
                    sc_name = sc.get('typeName', '')
                    if sc_id and sc_name:
                        sub_values.append({'n': sc_name, 'v': sc_id})
                if len(sub_values) > 1:
                    cat_filters.append({'key': 'label', 'name': '分类', 'value': sub_values})

            first_level = [v for v in self._video_type_list
                           if str(v.get('typePid', '')) == '0' and str(v.get('typeId', '')) == cid]
            if first_level:
                tags_str = first_level[0].get('tags', '')
                if tags_str:
                    tag_list = [t.strip() for t in tags_str.split(',') if t.strip()]
                    if tag_list:
                        tag_values = [{'n': '全部', 'v': ''}]
                        for t in tag_list:
                            tag_values.append({'n': t, 'v': t})
                        cat_filters.append({'key': 'tag', 'name': '标签', 'value': tag_values})

            cat_filters.append({'key': 'sort', 'name': '排序', 'value': [
                {'n': '最近更新', 'v': '0'},
                {'n': '最多播放', 'v': '1'},
                {'n': '最多收藏', 'v': '2'},
            ]})

            if cat_filters:
                filters[cid] = cat_filters

        classes.append({'type_id': 'actor', 'type_name': '女优'})

        _actors_filters = []
        _actors_filters.append({'key': 'height', 'name': '身高', 'value': [
            {'n': '身高', 'v': ''},
        ] + [{'n': f'{h}cm', 'v': str(h)} for h in range(150, 165)]})

        _actors_filters.append({'key': 'cup', 'name': '罩杯', 'value': [
            {'n': '罩杯', 'v': ''},
        ] + [{'n': f'{c}罩杯', 'v': c} for c in 'ABCDEFG']})

        _actors_filters.append({'key': 'birthday', 'name': '年龄', 'value': [
            {'n': '年龄', 'v': ''},
        ] + [{'n': f'{y}年', 'v': str(y)} for y in range(2002, 1975, -1)]})

        _actors_filters.append({'key': 'debut', 'name': '出道', 'value': [
            {'n': '出道', 'v': ''},
        ] + [{'n': f'{y}年', 'v': str(y)} for y in range(2025, 2000, -1)]})

        filters['actor'] = _actors_filters
        classes.append({'type_id': 'topic', 'type_name': '专题'})

        home_videos = self.categoryContent('home', 1, '', {})
        return {
            'class': classes,
            'filters': filters,
            'type': '影视',
            'list': home_videos.get('list', []),
            'page': home_videos.get('page', 1),
            'pagecount': home_videos.get('pagecount', 1),
            'limit': home_videos.get('limit', 0),
            'total': home_videos.get('total', 0),
        }

    def homeVideoContent(self, tid, pg, filter, extend):
        return self.categoryContent(tid or 'home', pg, filter, extend)

    def categoryContent(self, tid, pg, filter, extend):
        tid = str(tid)
        pg = int(pg)

        self._select_best_site()
        self._ensure_session()

        vod_list = []

        if '@' in tid:
            real_tid = tid.replace('@', '')
            if real_tid.startswith('actor_'):
                actor_id = real_tid[len('actor_'):]
                detail_resp = self._api_request('/ht/content/queryActorDetail', {
                    'actorId': actor_id,
                })
                actor_name = ''
                if detail_resp and detail_resp.get('code') == 10000:
                    detail_data = detail_resp.get('data', {})
                    actor_info = (detail_data.get('actorDetail') or detail_data or {})
                    actor_name = (actor_info.get('actorName') or actor_info.get('actor_name') or '')

                if actor_name:
                    resp = self._api_request('/ht/content/search', {
                        'keywords': actor_name,
                        'pageNo': str(pg - 1),
                        'pageSize': '20',
                    })
                else:
                    resp = self._api_request('/ht/content/queryTypeVideosH5', {
                        'actorId': actor_id,
                        'pageNo': str(pg - 1),
                        'pageSize': '20',
                        'type': '1',
                    })

                if not resp or resp.get('code') != 10000:
                    return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

                data = resp.get('data', {})
                vod_list = self._extract_videos_from_data(data)
                total_page = int(data.get('totalPage') or data.get('total_page') or 1)
                return {'list': vod_list, 'page': pg, 'pagecount': max(total_page, 1),
                        'limit': len(vod_list), 'total': max(total_page, 1) * 20}

            elif real_tid.startswith('topic_'):
                topic_id = real_tid[len('topic_'):]
                resp = self._api_request('/ht/content/queryOriTopicVideos', {
                    'topicId': topic_id,
                    'pageNo': str(pg - 1),
                    'pageSize': '20',
                })
                if not resp or resp.get('code') != 10000:
                    return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

                data = resp.get('data', {})
                vod_list = self._extract_videos_from_data(data)
                total_page = int(data.get('totalPage') or data.get('total_page') or 1)
                return {'list': vod_list, 'page': pg, 'pagecount': max(total_page, 1),
                        'limit': len(vod_list), 'total': max(total_page, 1) * 20}

            else:
                return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

        if tid == 'actor':
            api_params = {
                'pageNo': str(pg - 1),
                'pageSize': '20',
            }
            if isinstance(extend, dict):
                _actor_filter_map = {
                    'height': 'actorHeight',
                    'cup': 'cupSize',
                    'birthday': 'actorBirthday',
                    'debut': 'actorDebut',
                }
                for ek, ak in _actor_filter_map.items():
                    val = extend.get(ek, '')
                    if val:
                        api_params[ak] = val

            resp = self._api_request('/ht/content/getActors', api_params)
            if not resp or resp.get('code') != 10000:
                return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

            data = resp.get('data', {})
            vod_list = self._parse_actor_list(data)
            total_page = int(data.get('totalPage') or 1)
            return {'list': vod_list, 'page': pg, 'pagecount': total_page,
                    'limit': len(vod_list), 'total': total_page * 20}

        if tid == 'topic':
            resp = self._api_request('/ht/content/getOriTopicList', {
                'pageNo': str(pg - 1),
                'pageSize': '20',
            })
            if not resp or resp.get('code') != 10000:
                return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

            data = resp.get('data', {})
            vod_list = self._parse_topic_list(data)
            return {'list': vod_list, 'page': pg, 'pagecount': 50, 'limit': len(vod_list),
                    'total': len(vod_list) * 50}

        if tid in ('home', 'new', 'hot'):
            sort_map = {'home': '1', 'new': '1', 'hot': '2'}
            resp = self._api_request('/ht/content/queryTypeVideosH5', {
                'pageNo': str(pg - 1),
                'pageSize': '20',
                'sort': sort_map.get(tid, '1'),
                'type': '1',
            })
            if not resp or resp.get('code') != 10000:
                return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

            data = resp.get('data', {})
            items = (data.get('typeVideoList') or data.get('list') or data.get('data') or data.get('videoList') or [])
            if isinstance(items, list):
                for v in items:
                    parsed = self._parse_video(v)
                    if parsed:
                        vod_list.append(parsed)
        else:
            api_params = {
                'pageNo': str(pg - 1),
                'pageSize': '20',
                'typeId': tid,          
                'type': '1',            
            }
            if isinstance(extend, dict):
                for key in ('label', 'tag', 'sort'):
                    val = extend.get(key, '')
                    if val:
                        api_params[key] = val

            resp = self._api_request('/ht/content/queryTypeVideosH5', api_params)
            if not resp or resp.get('code') != 10000:
                return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

            data = resp.get('data', {})
            items = (data.get('typeVideoList') or data.get('list') or data.get('data') or data.get('videoList') or [])
            if isinstance(items, list):
                for v in items:
                    parsed = self._parse_video(v)
                    if parsed:
                        vod_list.append(parsed)

        total_page = int(data.get('totalPage') or 1)
        return {
            'list': vod_list,
            'page': pg,
            'pagecount': total_page,
            'limit': len(vod_list),
            'total': total_page * 20,
        }

    def _extract_videos_from_data(self, data):
        if isinstance(data, list):
            items = data
        elif not isinstance(data, dict):
            return []
        else:
            items = (data.get('videoList') or data.get('list') or data.get('data')
                     or data.get('videos') or data.get('typeVideoList')
                     or data.get('topicVideoIdList') or data.get('searchList')
                     or data.get('contentList') or data.get('records')
                     or data.get('pageData') or [])
        if not isinstance(items, list):
            return []
        return [p for v in items if (p := self._parse_video(v))]

    @staticmethod
    def _try_get(item, *keys):
        for k in keys:
            v = item.get(k)
            if v is not None and v != '':
                return v
        return ''

    def _parse_actor_list(self, data):
        if isinstance(data, list):
            items = data
        elif not isinstance(data, dict):
            return []
        else:
            items = (data.get('actorList') or data.get('actors') or data.get('list')
                     or data.get('data') or [])
        if not isinstance(items, list):
            return []

        results = []
        seen = set()
        for item in items:
            if not isinstance(item, dict):
                continue

            actor_id = str(self._try_get(item,
                'actorId', 'contentId', 'id', 'artId', 'actor_id', 'userId'))
            actor_name = str(self._try_get(item,
                'actorName', 'name', 'title', 'artName', 'actor_name', 'actor'))
            actor_img = str(self._try_get(item,
                'actorPic', 'actorImg', 'img', 'avatar', 'cover',
                'imageUrl', 'headImg', 'head', 'photo', 'image', 'pic', 'actor_img'))
            actor_count = str(self._try_get(item,
                'videoCount', 'contentCount', 'count', 'totalCount',
                'total', 'video_count'))

            if not actor_id:
                continue
            if actor_id in seen:
                continue
            seen.add(actor_id)

            if not actor_img:
                actor_img = self.host + '/favicon.ico'
            remarks = f'{actor_count}部' if actor_count else ''
            results.append({
                'vod_id': 'actor_' + actor_id + '@',
                'vod_name': actor_name or ('演员' + actor_id),
                'vod_pic': self.get_proxy_image_url(actor_img),
                'vod_tag': 'folder',
                'vod_remarks': remarks,
            })
        return results

    def _parse_topic_list(self, data):
        if isinstance(data, list):
            items = data
        elif not isinstance(data, dict):
            return []
        else:
            items = (data.get('topicList') or data.get('oriTopicList') or data.get('list')
                     or data.get('data') or data.get('topics') or [])
        if not isinstance(items, list):
            return []

        results = []
        seen = set()
        for item in items:
            if not isinstance(item, dict):
                continue

            topic_id = str(self._try_get(item,
                'topicId', 'id', 'contentId', 'oriTopicId', 'topic_id'))
            topic_name = str(self._try_get(item,
                'topicName', 'name', 'title', 'oriTopicName', 'topic_name', 'topic'))
            topic_img = str(self._try_get(item,
                'topicPic', 'topicImg', 'img', 'cover', 'imageUrl', 'pic',
                'thumb', 'image', 'topic_img', 'oriTopicImg'))
            topic_count = str(self._try_get(item,
                'videoCount', 'count', 'contentCount', 'totalCount',
                'total', 'video_count'))

            if not topic_id:
                continue
            if topic_id in seen:
                continue
            seen.add(topic_id)

            if not topic_img:
                topic_img = self.host + '/favicon.ico'
            remarks = f'{topic_count}部' if topic_count else ''
            results.append({
                'vod_id': 'topic_' + topic_id + '@',
                'vod_name': topic_name or ('专题' + topic_id),
                'vod_pic': self.get_proxy_image_url(topic_img),
                'vod_tag': 'folder',
                'vod_remarks': remarks,
            })
        return results

    def _parse_video(self, item):
        if item.get('contentType') == 3 and item.get('jumpScheme'):
            return None

        vid = str(item.get('contentId') or item.get('id') or item.get('videoId') or '')
        title = item.get('title') or item.get('name') or item.get('videoTitle') or ''
        pic = item.get('img') or item.get('cover') or item.get('coverUrl') or item.get('pic') or item.get('imageUrl') or ''
        remarks = item.get('duration') or item.get('playCount') or item.get('remark') or ''

        if remarks and str(remarks).isdigit():
            remarks = self._fmt_duration(remarks)

        return {
            'vod_id': vid,
            'vod_name': title,
            'vod_pic': self.get_proxy_image_url(pic) if pic else '',
            'vod_remarks': str(remarks) if remarks else '',
        }

    def detailContent(self, ids):
        did = ids[0] if isinstance(ids, list) else ids

        self._select_best_site()
        self._ensure_session()

        resp = self._api_request('/ht/content/detail', {'contentId': str(did)})
        if not resp or resp.get('code') != 10000:
            return {'list': []}

        detail = resp.get('data', {})
        if not detail:
            return {'list': []}

        title = (detail.get('title') or detail.get('name') or
                 detail.get('videoTitle') or '未知标题')
        pic = (detail.get('cover') or detail.get('coverUrl') or
               detail.get('img') or detail.get('imageUrl') or '')
        desc = detail.get('description') or detail.get('desc') or detail.get('intro') or ''
        duration = detail.get('duration', 0)
        actor = detail.get('actor') or detail.get('actors') or ''

        # 适配 FongMi: vod_play_url = '源名称$播放ID'
        vod_play_url = '蜜桃源$' + str(did)

        return {'list': [{
            'vod_id': str(did),
            'vod_name': title,
            'vod_pic': self.get_proxy_image_url(pic) if pic else '',
            'vod_actor': str(actor) if actor else '',
            'vod_director': '',
            'vod_content': desc,
            'vod_year': '',
            'vod_area': '',
            'vod_remarks': self._fmt_duration(duration),
            'vod_play_from': '蜜桃视频',
            'vod_play_url': vod_play_url,
            'type': 'video',
        }]}

    def searchContent(self, key, quick, pg=1):
        self._select_best_site()
        self._ensure_session()

        pg = int(pg)
        resp = self._api_request('/ht/content/search', {
            'keywords': key,
            'pageNo': pg - 1,
            'pageSize': 20,
        })
        if not resp or resp.get('code') != 10000:
            return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

        data = resp.get('data', {})

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = (data.get('searchList')
                  or data.get('list')
                  or data.get('data')
                  or data.get('videoList')
                  or data.get('records')
                  or data.get('resultList')
                  or data.get('content')
                  or [])
        else:
            return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

        if not isinstance(items, list):
            return {'list': [], 'page': pg, 'pagecount': 1, 'limit': 0, 'total': 0}

        vod_list = [p for v in items if (p := self._parse_video(v))]
        total_page = int(data.get('totalPage') or 1) if isinstance(data, dict) else max(1, len(vod_list) // 20)
        return {
            'list': vod_list,
            'page': pg,
            'pagecount': total_page,
            'limit': len(vod_list),
            'total': total_page * 20,
        }

    # ============================================================
    # 核心修正：规范的 FongMi 播放器接口，确保能正常解析播放
    # ============================================================
    def playerContent(self, flag, id, vipFlags=None):
        """
        FongMi 专用的播放器接口方法。
        当客户端点击播放时，FongMi 会调用这个方法，传入上面 detailContent 里绑定好的唯一标识（ID）。
        """
        self._select_best_site()
        self._ensure_session()

        # id 即为我们在 detailContent 绑定返回的视频 did
        video_id = id

        resp = self._api_request('/ht/content/detail', {'contentId': str(video_id)})
        if not resp or resp.get('code') != 10000:
            return {'parse': 0, 'url': '', 'jx': 0}

        detail = resp.get('data', {})
        play_url = (detail.get('videoUrl') or detail.get('playUrl') or
                    detail.get('url') or detail.get('m3u8Url') or
                    detail.get('sl') or '')

        if not play_url:
            return {'parse': 0, 'url': '', 'jx': 0}

        return {
            'parse': 0,      # 0代表直接播放
            'url': play_url,  # 真实的 .m3u8 / .mp4 视频流地址
            'jx': 0,
            'header': {
                'User-Agent': self.headers['User-Agent'],
                'Referer': self.host + '/',
            },
        }

    # ============================================================
    # 图片代理
    # ============================================================
    def localProxy(self, params):
        try:
            if params.get('type') != PROXY_TYPE:
                return [404, 'text/plain', 'not found']

            img_url = params.get('url', '')
            if not img_url:
                return [400, 'text/plain', 'missing url']

            img_url = unquote(img_url)

            r = requests.get(img_url, headers={
                'User-Agent': self.headers['User-Agent'],
                'Referer': self.host + '/',
            }, timeout=TIMEOUT, verify=False)

            if r.status_code != 200:
                return [404, 'text/plain', 'image not found']

            data = r.content

            # XOR 0x88 自动解密 (蜜桃图片防盗链)
            if data[:2] != b'\xff\xd8' and data[:4] != b'\x89PNG' \
                    and not (data[:4] == b'RIFF' and data[8:12] == b'WEBP'):
                decoded = bytes(b ^ 0x88 for b in data)
                if decoded[:2] == b'\xff\xd8' or decoded[:4] == b'\x89PNG' \
                        or (decoded[:4] == b'RIFF' and decoded[8:12] == b'WEBP'):
                    data = decoded

            if data[:2] == b'\xff\xd8':
                return [200, 'image/jpeg', data, {'Content-Length': str(len(data))}]
            elif data[:4] == b'\x89PNG':
                return [200, 'image/png', data, {'Content-Length': str(len(data))}]
            elif data[:4] == b'RIFF' and data[8:12] == b'WEBP':
                return [200, 'image/webp', data, {'Content-Length': str(len(data))}]
            else:
                mime = r.headers.get('Content-Type', 'image/jpeg')
                if mime.startswith('image/'):
                    return [200, mime, data, {'Content-Length': str(len(data))}]
                return [404, 'text/plain', 'invalid image format']
        except Exception:
            return [500, 'text/plain', 'proxy error']
