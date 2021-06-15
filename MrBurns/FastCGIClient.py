"""
Modified from https://github.com/wuyunfeng/Python-FastCGI-Client
"""
import random

class FastCGIClient:
    __FCGI_VERSION = 1
    __FCGI_ROLE_RESPONDER = 1
    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_HEADER_SIZE = 8

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        return chr(FastCGIClient.__FCGI_VERSION) \
               + chr(fcgi_type) \
               + chr((requestid >> 8) & 0xFF) \
               + chr(requestid & 0xFF) \
               + chr((length >> 8) & 0xFF) \
               + chr(length & 0xFF) \
               + chr(0) \
               + chr(0) \
               + content

    def __encodeNameValueParams(self, name, value):
        nLen = len(str(name))
        vLen = len(str(value))
        record = ''
        if nLen < 128:
            record += chr(nLen)
        else:
            record += chr((nLen >> 24) | 0x80) \
                      + chr((nLen >> 16) & 0xFF) \
                      + chr((nLen >> 8) & 0xFF) \
                      + chr(nLen & 0xFF)
        if vLen < 128:
            record += chr(vLen)
        else:
            record += chr((vLen >> 24) | 0x80) \
                      + chr((vLen >> 16) & 0xFF) \
                      + chr((vLen >> 8) & 0xFF) \
                      + chr(vLen & 0xFF)
        return record + str(name) + str(value)

    def request(self, nameValuePairs={}, post=''):
        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = ""
        beginFCGIRecordContent = chr(0) \
                                 + chr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + chr(self.keepalive) \
                                 + chr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = ''
        if nameValuePairs:
            for name, value in nameValuePairs.items():
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, '', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, post, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, '', requestId)
        return request
