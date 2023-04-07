#!/usr/bin/env python3
import base64
import json
import os

import requests
from Crypto.Cipher import AES
from flask import Flask, request, Response

key = b'0'*16

def decrypt(key, data, return_str=True):
    """
    Decrypts data using key checking data integrity using the embedded MAC tag
    :param key: key to use decrypt data
    :param data: data to be decrypted
    :param return_str: should the data be changed to str
    :return: a str or bytes object
    :raises ValueError: when the encrypted data was modified post encryption
    """
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    if return_str:
        try:
            decrypted_data = str(decrypted_data, 'utf-8')
        except UnicodeError as e:
            pass
    return decrypted_data

def encrypt(key, data):
    """
    Encrypts data using key
    :param key: key to use to encrypt data
    :param data: data to be encrypted
    :return: encrypted data with nonce and MAC tag prepended
    """
    if type(data) == str:
        data = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_data = cipher.nonce + tag + ciphertext
    return encrypted_data


def get_input(data):
    if type(data) == str:
        data = bytes(data, 'utf-8')
    data = base64.urlsafe_b64decode(data)
    data = decrypt(key, data, False)
    return data

app = Flask(__name__)

@app.route('/<headers>/<url>/get.jpg')
def get(headers, url):
    headers = get_input(headers)
    url = get_input(url)
    data = requests.get(url, headers=json.loads(headers), allow_redirects=True).content
    data = encrypt(key, data)
    return Response(data, mimetype='image/jpg')


@app.route('/<headers>/<post_data>/<url>/post.jpg')
def post(headers, post_data, url):
    headers = get_input(headers)
    post_data = get_input(post_data)
    url = get_input(url)
    print(post_data)
    data = requests.post(url, data=post_data, headers=json.loads(headers), allow_redirects=True).content
    data = encrypt(key, data)
    return Response(data, mimetype='image/jpg')



@app.route('/<headers>/<url>/<int:start>/<int:stop>/stream.jpg')
def stream(headers, url, start, stop):
    headers = get_input(headers)
    url = get_input(url)
    print(url, start, stop)
    resp = requests.get(url, headers=json.loads(headers), allow_redirects=True, stream=True)
    left = start
    data = b''
    for chunk in resp.iter_content(7*1024*1024):
        if left:
            if left > len(chunk):
                left -= len(chunk)
            else:
                data += chunk[left:]
                left = 0
        else:
            data += chunk
            if len(data) > (stop-start):
                data = data[:(stop-start)]
                break
    data = encrypt(key, data)
    return Response(data, mimetype='image/jpg')


if __name__ == '__main__':
    app.run(host="::", port=int(os.environ.get('PORT', 8100)), debug=True)
