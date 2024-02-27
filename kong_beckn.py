#!/usr/bin/env python3
import os
import kong_pdk.pdk.kong as kong
import requests
import json
import base64
import hashlib
import ed25519
Schema = (
    {'authorization_header':{'type':'string'}},
    {'beckn_gateway_url':{'type':'string'}}
)
version = '0.1.0'
priority = 0
class BecknPlugin(object):
    def __init__(self, config):
        self.config = config

    def create_digest(self,created,expires,request_body:str):
        message_str = hashlib.blake2b(request_body.encode(), digest_size=64).digest()
        digest_base64 = base64.b64encode(message_str).decode()
        signing_string= '(created): '+created+'\n'+'(expires): '+expires+'\n'+'digest: BLAKE-512='+digest_base64
        return signing_string
    def verify_signature(self,public_key:str,signature:str,signing_str:str):
        signature_bytes = base64.b64decode(signature)
        vk = ed25519.VerifyingKey(base64.b64decode(public_key))
        try:
            vk.verify(signature_bytes, signing_str.encode())
            return True
        except ed25519.BadSignatureError:
            return False

    def access(self, kong: kong.kong):
        auth_header='X-Gateway-Authorization'
        url='https://sandbox.onest.network/onest/lookup'
        try:
            if 'authorization_header' in self.config:
                auth_header=self.config['authorization_header']
            if 'beckn_gateway_url' in self.config:
                url=self.config['beckn_gateway_url']
            auth_components=auth_header.split(",")
            auth_info={}
            for part in auth_components:
                key,value=part.strip().split("=",1)
                if key.startswith("Signature"):
                    key=key.split()[1]
                value=value.strip('"')
                auth_info[key]=value
            subscriber_id, unique_key_id, algorithm=auth_info["keyId"].split("|")
            if algorithm != auth_info["algorithm"]:
                return kong.response.exit(400,'Algorithm incoorect')
            try:
                data={'unique_key_id':unique_key_id,'country':'IND','type':'BPP'}
                headers={'Content-Type':'application/json'}
                response=requests.post(url=url,data=json.dumps(data),headers=headers)
                public_key=response.json()[0]['']
                request_body=kong.request.get_raw_body()
                digest= self.create_digest(auth_info['created'],auth_info['expires'],str(request_body))
                if self.verify_signature(public_key=public_key,signature=auth_info['signature'],signing_str=digest):
                    kong.log('Signature Verified')
                else:
                    return kong.log.response.exit(400,{})

            except Exception as e1:
                return kong.response.exit(401,{ 'msg':'Unauthorized'})
        except Exception as e:
            return kong.response.exit(400,{ 'msg':''})

