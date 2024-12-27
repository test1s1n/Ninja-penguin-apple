import requests
import os
from urllib3.exceptions import InsecureRequestWarning
from Crypto.Cipher import AES
from Crypto import Random
import typing
import base64

CHUNK_SIZE = 500

requiredEnvVars = ["METHOD_HEX", "URL_HEX", "HEADERS_HEX", "BODY_HEX", "AES256_KEY_HEX"]
missingEnvVars = [var for var in requiredEnvVars if os.getenv(var) is None]

if missingEnvVars:
    missingVarsStr = ", ".join(missingEnvVars)
    raise ValueError(f"Missing environment variables: {missingVarsStr}")

envMethod = bytes.fromhex(os.getenv("METHOD_HEX"))
envURL = bytes.fromhex(os.getenv("URL_HEX"))
envHeaders = bytes.fromhex(os.getenv("HEADERS_HEX", default=""))
envBody = bytes.fromhex(os.getenv("BODY_HEX", default=""))
aesKey = bytes.fromhex(os.getenv("AES256_KEY_HEX", default=""))

def aes256_encrypt(data: bytes, key: bytes) -> str:
    """
         Encrypt using AES-256-GCM random iv
        'key' must be bytes from hex, generate with 'openssl rand -hex 32'
         Returns a hex str
    """
    try:
        iv = Random.get_random_bytes(12) # Recommended nonce size for AES GCM : 12 bytes

        cipher = AES.new(key, AES.MODE_GCM, iv)

        cipher_data = cipher.encrypt(data)
        tag = cipher.digest()

        result = iv.hex()+cipher_data.hex()+tag.hex() # Result : IV + CIPHER DATA + TAG (Tag is used by GCM for authentication purposes)
    except Exception as e:
        print("Cannot encrypt datas...")
        print(e)
        exit(1)
    return result

def aes256_decrypt(encryptedData: bytes, key: bytes) -> bytes:
    """
         Decrypt using AES-256-GCM random iv
        'keyHexStr' must be in hex, generate with 'openssl rand -hex 32'
    """
    try:
        iv = encryptedData[:12]
        encrypted_data = encryptedData[12:-16]
        tag = encryptedData[-16:]

        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt_and_verify(encrypted_data, tag)
    except Exception as e:
        print("Cannot decrypt data...")
        print(e)
        exit(1)
    return decrypted

def parseInputs(envMethod: bytes, envURL: bytes, envHeaders: bytes, envBody: bytes, aesKey: bytes) -> typing.Tuple[bytes, bytes, bytes, bytes]:
    method = aes256_decrypt(envMethod, aesKey)
    url = aes256_decrypt(envURL, aesKey)
    
    headers = {}
    if len(envHeaders) > 0:
        headersRaw = aes256_decrypt(envHeaders, aesKey)
        headersLines = headersRaw.splitlines()
        if len(headersLines)%2 != 0:
            raise Exception("Can not parse the request headers.")

        for i in range(0, len(headersLines), 2):
            headers[headersLines[i]] = headersLines[i+1]

    body = None
    if len(envBody) > 0:
        body = aes256_decrypt(envBody, aesKey)

    return method, url, headers, body

def encryptOutputs(status: int, headers: dict, body: bytes, aesKey: bytes) -> typing.Tuple[str, str, str]:
    statusHex = ""
    if status != None:
        statusHex = aes256_encrypt(str(status).encode(), aesKey)

    headersStr = ""
    if headers != None:
        for key in headers:
            headersStr += key + "\n" + headers[key] + "\n"
        if len(headersStr) > 0:
            headersStr = headersStr[:-1]
    headersHex = aes256_encrypt(headersStr.encode(), aesKey)

    bodyHex = ""
    if body != None:
        bodyHex = aes256_encrypt(body, aesKey)

    return statusHex, headersHex, bodyHex

def makeRequest(method: str, url: str, headers:dict=None, body:bytes=None) -> typing.Tuple[int, dict, bytes, str]:
    try:
        response = requests.request(method, url, headers=headers, data=body, verify=False, allow_redirects=False, stream=True)
    
        status = response.status_code
        headers = response.headers
        body = response.raw.read()

        return status, headers, body, None
    except requests.RequestException as e:
        return None, None, None, base64.b64encode(str(e).encode()).decode()

reqMethod, reqURL, reqHeaders, reqBody = parseInputs(envMethod, envURL, envHeaders, envBody, aesKey)

respStatus, respHeaders, respBody, respErr = makeRequest(reqMethod, reqURL, reqHeaders, reqBody)

if respErr != None:
    print("RESP_ERR", respErr)
else:
    respStatusHex, respHeadersHex, respBodyHex = encryptOutputs(respStatus, respHeaders, respBody, aesKey)

    print("RESP_STATUS_ENCRYPTED_HEX", respStatusHex)
    # print("RESP_HEADERS_ENCRYPTED_HEX", respHeadersHex)
    for i in range(0, len(respHeadersHex), CHUNK_SIZE):
        print("RESP_HEADERS_ENCRYPTED_HEX", respHeadersHex[i:i + CHUNK_SIZE])
    # print("RESP_BODY_ENCRYPTED_HEX", respBodyHex)
    for i in range(0, len(respBodyHex), CHUNK_SIZE):
        print("RESP_BODY_ENCRYPTED_HEX", respBodyHex[i:i + CHUNK_SIZE])