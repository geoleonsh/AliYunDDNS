#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import time
import requests
from alidns import ManageDNS

'''
西窗浪人，版权所有，https://www.bigxd.com
'''
# 设置阿里云的域名、DNS记录、AccessKeyId和AccessKeySecret
AccessKeyId = 'AAAAAA'
AccessKeySecret = '123456'
Domain = 'bigxd.com'
Value = 'www'
# 记录类型如果是ipv4地址，则为"A"，保持默认即可
Type = 'A'

MDNS = ManageDNS(id=AccessKeyId, key=AccessKeySecret)


# 获取本地IP
def get_ip_addr():
    tries = 0
    while tries < 10:
        try:
            response = requests.get('http://2018.ip138.com/ic.asp', timeout=3)
            break
        except Exception as e:
            tries += 1
            if tries == 10:
                response = None
                print(e)
    if response is not None:
        response.encoding = 'gb2312'
        message = response.text
        key = '您的IP是：(.*)来自'
        pattern = re.compile(key)
        result = pattern.findall(message)[0]
        result = re.sub('\[|\]', '', result).strip()
        return result
    else:
        return None


# 运行
ip = get_ip_addr()
if ip is not None:
    if MDNS.add(Domain, Value, Type, ip):
        print('增加记录成功')
time.sleep(60)
while True:
    ip = get_ip_addr()
    if ip is not None:
        if MDNS.modify(Domain, Value, Type, ip):
            print('修改记录成功,当前IP为' + ip)
        else:
            print('IP没有改变，阿里云报错400，可忽略。IP:' + ip)
        time.sleep(600)
