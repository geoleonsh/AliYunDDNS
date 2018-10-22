#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import datetime
import hashlib
import hmac
import json
import random
import urllib
import urllib.parse
import urllib.request

'''
西窗浪人，版权所有，https://www.bigxd.com
'''


class AliyunDDNS(object):
    def __init__(self, access_id, access_sec):
        self.ApiUrl = 'https://alidns.aliyuncs.com/?'
        self.Format = 'JSON'
        self.Version = '2015-01-09'
        self.AccessKeyId = access_id
        self.AccessKeySecret = access_sec
        self.SignatureMethod = 'HMAC-SHA1'
        self.SignatureVersion = '1.0'

    def get_signature(self, get_body):
        # 获取时间戳
        time_stamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        # 获取随机数字符串
        signature_nonce = str(int(random.random() * 100000000000000))
        common_dict = {'Format': self.Format, 'Version': self.Version, 'AccessKeyId': self.AccessKeyId,
                       'SignatureMethod': self.SignatureMethod, 'SignatureVersion': self.SignatureVersion,
                       'Timestamp': time_stamp, 'SignatureNonce': signature_nonce}
        # sign_dict = {**common_dict, **get_body}
        # 合并请求参数字典
        sign_dict = dict(common_dict.items() | get_body.items())
        # 按key值排序字典
        odered_sign_list = sorted(sign_dict.items(), key=lambda x: x[0])
        odered_sign_dict = dict(odered_sign_list)
        # url编码已排序字典
        url = urllib.parse.urlencode(odered_sign_dict)
        # 拼接欲签名字符串
        string_to_sign = 'GET' + '&%2F&' + urllib.parse.quote(url)
        # HMAC密钥，转化为Bytes类型
        hash_key = self.AccessKeySecret + '&'
        b_hash_key = hash_key.encode()
        b_string_to_sign = string_to_sign.encode()
        # HMAC加密
        hashing = hmac.new(b_hash_key, b_string_to_sign, hashlib.sha1).digest()
        # Base64编码
        signature = str(base64.b64encode(hashing), 'utf-8')
        req_url = url + '&Signature=' + signature
        return req_url

    def get_dns_record(self, domain):
        get_body = {
            'Action': 'DescribeDomainRecords',
            'DomainName': domain
        }
        url = self.ApiUrl + self.get_signature(get_body)
        times = 0
        while times < 5:
            try:
                req = urllib.request.Request(url)
                result = urllib.request.urlopen(req).read().decode()
                records = json.loads(result)['DomainRecords']['Record']
                return records
            except Exception as e:
                times += 1
                if times == 5:
                    print(e)

    def add_dns_record(self, domain, rr, d_type, value):
        get_body = {
            'Action': 'AddDomainRecord',
            'DomainName': domain,
            'RR': rr,
            'Type': d_type,
            'Value': value
        }
        url = self.ApiUrl + self.get_signature(get_body)
        times = 0
        while times < 5:
            try:
                req = urllib.request.Request(url)
                result = urllib.request.urlopen(req).read().decode()
                return result
            except Exception as e:
                times += 1
                if times == 5:
                    print(e)

    def modify_dns_record(self, record_id, rr, d_type, value):
        get_body = {
            'Action': 'UpdateDomainRecord',
            'RecordId': record_id,
            'RR': rr,
            'Type': d_type,
            'Value': value
        }
        url = self.ApiUrl + self.get_signature(get_body)
        times = 0
        while times < 5:
            try:
                req = urllib.request.Request(url)
                result = urllib.request.urlopen(req).read().decode()
                return result
            except Exception as e:
                times += 1
                if times == 5:
                    print(e)

    def delete_dns_record(self, record_id):
        get_body = {
            'Action': 'DeleteDomainRecord',
            'RecordId': record_id
        }
        url = self.ApiUrl + self.get_signature(get_body)
        times = 0
        while times < 5:
            try:
                req = urllib.request.Request(url)
                result = urllib.request.urlopen(req).read().decode()
                return result
            except Exception as e:
                times += 1
                if times == 5:
                    print(e)


class ManageDNS(object):
    def __init__(self, **kwargs):
        access_id = kwargs['id']
        access_sec = kwargs['key']
        self.ali_ddns = AliyunDDNS(access_id, access_sec)

    def add(self, domain, rr, d_type, value):
        records = self.ali_ddns.get_dns_record(domain)
        check = False
        dns = []
        if records:
            for record in records:
                dns.append(record['RR'])
            if rr not in dns:
                check = True
                result = self.ali_ddns.add_dns_record(domain, rr, d_type, value)
                if result is not None:
                    return True
        else:
            check = True
            result = self.ali_ddns.add_dns_record(domain, rr, d_type, value)
            if result is not None:
                return True
        if not check:
            print('已有此条记录，无法增加')

    def modify(self, domain, rr, d_type, value):
        records = self.ali_ddns.get_dns_record(domain)
        check = False
        if records:
            for record in records:
                if rr == record['RR']:
                    record_id = record['RecordId']
                    check = True
                    result = self.ali_ddns.modify_dns_record(record_id, rr, d_type, value)
                    if result is not None:
                        return True
        if not check:
            print('没有找到此条记录，无法修改')

    def delete(self, domain, rr):
        records = self.ali_ddns.get_dns_record(domain)
        check = False
        if records:
            for record in records:
                if rr == record['RR']:
                    record_id = record['RecordId']
                    check = True
                    result = self.ali_ddns.delete_dns_record(record_id)
                    if result is not None:
                        return True
        if not check:
            print('没有找到此条记录，无需删除')
