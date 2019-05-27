#-*-coding=utf-8-*-
# date: 2019/05/09
# 提交人：嘿嘿嘿-周琪
# 文件目录结构：
'''
|---根目录
    |-- topic2.py
    |-- 日志
       |-- 2018-12.01.csv
       |-- ...
    |-- 拓展数据
       |-- 360威胁情报数据.json
       |-- ...
'''

import json
import pandas as pd
import numpy as np
import collections

def main():
    # 数据载入
    # 360威胁情报数据
    data_360 = pd.read_json(path_or_buf='拓展数据/360威胁情报数据.json', orient=None, typ='frame',\
         dtype=True, convert_axes=True, convert_dates=True, keep_default_dates=True, numpy=False, \
         precise_float=False, date_unit=None, encoding=None, lines=False, chunksize=None, compression='infer')
    # domain_info数据
    domain_info = pd.read_csv('拓展数据/domain_info.csv', header=None)
    domain_info.columns = ['ip', 'time', 'domain', 'whois']
    # 部分终端可疑样本数据
    terminal = pd.read_csv('拓展数据/部分终端可疑样本.csv', header=None)
    terminal.columns = ['ip', 'md5', 'mid', 'time']
    # 可疑样本md5与文件名映射
    f = open('拓展数据/可疑样本md5与文件名映射.json')
    for i in f:
        filename = json.loads(i)

    # 数据分析
    ip_list = data_360.keys()
    mal_list = dict()
    for i in ip_list:
        mal_list[i] = data_360[i].summary['malicious_label']
        if not data_360[i].summary['malicious_label']:
            # 检查是否为僵尸主机
            if data_360[i].summary['is_botnet']:
                mal_list[i] = ['BOTNET']
    
    # 筛选出僵尸主机
    botnet_list = dict()
    for i in mal_list:
        try:
            botnet_list[i] = list(data_360[i].botnet_info[0].values())
        except:
            continue

    botnet = pd.DataFrame(botnet_list).T
    botnet = botnet.reset_index()
    botnet.columns = ['ip', 'time', 'type', 'famaily']
    print('DGA家族个数为： ', botnet['famaily'].unique().size)

    # 攻击者刻画
    spam_list = dict()
    for i in mal_list:
        if 'SPAM' in data_360[i].summary['malicious_label']: 
            # 需要考虑whitelist，即流量出口度量
            try:
                whitelist = data_360[i].summary['whitelist']
            except:
                whitelist = None
            if data_360[i].summary['is_botnet']: # 将botnet筛选出去
                continue
            spam_list[i] = ['SPAM', whitelist]
    
    spam = pd.DataFrame(spam_list).T
    spam = spam.reset_index()
    spam.columns = ['ip', 'type', 'whitelist']
    print('spam主机个数为：', spam['ip'].size)

    # SPAM主机IP-域名信息映射
    domain_info = domain_info[domain_info['domain'] != '[]']
    count = 0
    sd_list = []
    for i in spam['ip']:
        if i in domain_info['ip'].tolist():
            sd_list.append(i)
            count += 1
    print('SPAM攻击者数量为：%d' % count)

    # 局域网IP聚类
    spam_cate = collections.defaultdict(list)
    for i in range(len(sd_list)):
        if sd_list[i] in sum(list(spam_cate.values()), []):
            continue
        ip = [sd_list[i]]
        for j in range(i+1, len(sd_list)):
            if sd_list[i].split('.')[:3] == sd_list[j].split('.')[:3]: # 属于同一局域网
                ip.append(sd_list[j])
        spam_cate[i] = ip
    print('SPAM攻击者分类：\n', spam_cate)

    # Web攻击者分析
    web_attackers = list()
    for i in ip_list:
        if 'WEB_ATTACKER' in data_360[i].summary['malicious_label']:
            web_attackers.append(i)

    # 局域网IP聚类
    web_cate = collections.defaultdict(list)
    for i in range(len(web_attackers)):
        if web_attackers[i] in sum(list(web_cate.values()), []):
            continue
        ip = [web_attackers[i]]
        for j in range(i+1, len(web_attackers)):
            if web_attackers[i].split('.')[:3] == web_attackers[j].split('.')[:3]: # 属于同一局域网
                ip.append(web_attackers[j])
        web_cate[i] = ip
    print('Web攻击者分类: \n', web_cate)

    # spam_domain数据构造
    spam_domain = dict()
    for i in sd_list:
        domain = domain_info[domain_info['ip']==i]['domain'].tolist()
        whois = domain_info[domain_info['ip']==i]['whois'].tolist()
        spam_domain[i] = [domain, whois]
    
    spam_domain = pd.DataFrame(spam_domain).T
    spam_domain = spam_domain.reset_index()
    spam_domain.columns = ['ip', 'domain', 'whois']

    # IP-恶意样本映射
    terminal['md5'] = terminal['md5'].map(filename)
    terminal.rename(columns={'md5':'malware'}, inplace=True)
    terminal.drop_duplicates('mid', inplace=True)
    
    ip_malware = dict()
    for i in terminal['ip'].unique():
        try:
            ip_malware[i] = sum(terminal[terminal['ip']==i]['malware'].tolist(), [])
        except:
            continue

if __name__ == "__main__":
    main()