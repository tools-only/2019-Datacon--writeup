#-*-coding=utf-8-*-
# date: 2019/05/10
# 提交人：嘿嘿嘿-周琪
# 文件目录结构：
'''
|---根目录
    |-- topic3.py
    |-- result.csv
    |-- botnet.csv
    |-- sd_list.txt
    |-- web_attackers.csv
    |-- 日志
       |-- 2018-12.01.csv
       |-- ...
    |-- 拓展数据
       |-- 360威胁情报数据.json
       |-- ...
'''

import pandas as pd 
import numpy as np
import gc
import json
import collections
import matplotlib.pyplot as plt
%matplotlib inline 
import seaborn as sns
log_path = './日志/'

def main():
    # 读取题目一得到的攻击样本index
    submission = pd.read_csv('result.csv')
    ip_list = submission['file_id'].tolist()
    # 读取botnet数据（题目二的部分结果数据）
    botnet = pd.read_csv('botnet.csv') # botnet.csv为题目二解题中得到的dga家族
    # 读取Spam攻击者数据
    spam_list= np.loadtxt(open("sd_list.txt",encoding='utf-8'),dtype=np.str,delimiter=None,unpack=False)
    # 读取web攻击者数据
    web_list =  np.loadtxt(open("web_attackers.csv",encoding='utf-8'),dtype=np.str,delimiter=None,unpack=False)

    # 读取domain_category数据
    with open('拓展数据/domain_category.json','r') as load_f:
        load_dict = json.load(load_f)

    # 读取日志中的攻击数据
    mal_list = pd.DataFrame()
    for i in range(1, 32):
        print('当前迭代： %d' % i)
        if i == 26:
            continue
        if i < 10:
            path = log_path+'2018-12-0'+str(i)+'.csv'
        else:
            path = log_path+'2018-12-'+str(i)+'.csv'
        data = open(path, encoding='utf-8')
        data = pd.read_csv(data, header=None)
    
        mal_list = mal_list.append(data[data[0].isin(ip_list)])
        # 手动释放内存
        del data
        gc.collect()
    
    mal_list.columns = ['ip', 'time', 'domain', 'http', 'post', 'parameter', 'url',\
                        'user-agent', 'cookie', 'x-forwarded-for', 'country(domain)',\
                        'province(domain)','city(domain)','country(ip)',\
                        'province(ip)', 'city(ip)']

    # 将攻击日志文件的domain进行类别的映射
    mal_list['domain_category'] = mal_list['domain'].map(load_dict)

    '''
    spam攻击者分析
    '''
    # domain行业分布情况
    domain_cate = collections.defaultdict(list)
    for i in spam_list:
        cate = []
        domain_cate[i] = mal_list[mal_list['ip']==i]['domain_category'].tolist()
        
    # domain地理位置分布情况
    domain_loc = collections.defaultdict(list)
    for i in spam_list:
        cate = []
        domain_loc[i] = mal_list[mal_list['ip']==i]['province(domain)'].tolist()
    print('spam攻击中受害domain的地理分布情况：', domain_loc)

    '''
    web攻击者分析
    '''
    # domain行业分布情况
    web_domain_cate = collections.defaultdict(list)
    for i in web_list:
        cate = []
        web_domain_cate[i] = mal_list[mal_list['ip']==i]['domain_category'].tolist()
    
    web_domain_list = []
    for i in web_list:
        tem = dict()
        if web_domain_cate[i]:
            for cate in np.unique(web_domain_cate[i]):
                tem[cate] = 0
            for j in web_domain_cate[i]:
                tem[j] += 1
        web_domain_list.append(tem)
    print('第14个web攻击者示例：', web_domain_list[13])
    
    # 作图分析
    # 饼图
    plt.rcParams['font.sans-serif'] = ['KaiTi']

    patches, l_text, p_text = plt.pie(web_domain_list[13].values(), labels=web_domain_list[13].keys(), autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20
    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # 柱状图分析
    plt.bar(web_domain_list[13].keys(), web_domain_list[13].values())
    plt.xticks(rotation=45)
    plt.show()

    # domain地理位置分布情况
    web_domain_loc = collections.defaultdict(list)
    for i in web_list:
    #     cate = []
        country = mal_list[mal_list['ip']==i]['country(domain)'].tolist()
        province = mal_list[mal_list['ip']==i]['province(domain)'].tolist()
        city = mal_list[mal_list['ip']==i]['city(domain)'].tolist()
        loc = [country, province, city]
        web_domain_loc[i] = loc

    '''
    DGA僵尸网络分析
    '''
    mal_list = mal_list.drop(['http','post','parameter','url','user-agent','cookie', 'time', 'x-forwarded-for', 'domain'], axis=1)
    # 抽取Trojan对应的ip日志数据
    Trojan_list = dga[dga['family'].isin(['Trojan'])]['ip'].tolist()
    Trojan_mal = mal_list[mal_list['ip'].isin(Trojan_list)]
    Trojan_mal = Trojan_mal.drop(['domain'], axis=1)

    # domain行业分布情况
    print('domain行业分布情况：', Trojan_mal['domain_category'].value_counts())
    patches, l_text, p_text = plt.pie(Trojan_mal['domain_category'].value_counts().values, labels=Trojan_mal['domain_category'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20

    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # domain地理位置分布情况
    # 国家分布
    patches, l_text, p_text = plt.pie(Trojan_mal['country(domain)'].value_counts().values, labels=Trojan_mal['country(domain)'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20

    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # 省/直辖市分布
    patches, l_text, p_text = plt.pie(Trojan_mal['province(domain)'].value_counts().values, labels=Trojan_mal['province(domain)'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20

    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # 城市分布
    patches, l_text, p_text = plt.pie(Trojan_mal['city(domain)'].value_counts().values, labels=Trojan_mal['city(domain)'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20

    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # 僵尸IP地理位置分布情况
    patches, l_text, p_text = plt.pie(Trojan_mal['country(ip)'].value_counts().values, labels=Trojan_mal['country(ip)'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20

    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # 省/直辖市分布
    patches, l_text, p_text = plt.pie(Trojan_mal['province(ip)'].value_counts().values, labels=Trojan_mal['province(ip)'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
    for t in l_text:
        t.set_size = 30
    for t in p_text:
        t.set_size = 20

    plt.axis('equal')
    plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
    plt.grid()
    plt.show()

    # 城市分布
patches, l_text, p_text = plt.pie(Trojan_mal['city(ip)'].value_counts().values, labels=Trojan_mal['city(ip)'].value_counts().index, autopct='%2.0f%%',startangle=90,pctdistance=0.6)
for t in l_text:
    t.set_size = 30
    
for t in p_text:
    t.set_size = 20

plt.axis('equal')
plt.legend(loc='upper left', bbox_to_anchor=(-0.1, 1))
plt.grid()
plt.show()