# wooscan
批量查询网站在乌云是否存在忽略的sql注入漏洞并自动调用sqlmap测试

脚本属于初学期作品，代码有些渣，但一开始想要的功能勉强算实现了，以后继续改进。

使用方法:
将域名列表放至url.txt文件中，为了更好的成功率，格式最好为baidu.com这种不带www或子域名的的主域名形式
然后运行python wooscan.py即可
测试环境是kali+python2
python3暂时懒得改=_=

-h,--help               显示帮助信息并退出
-f  文件名.txt          域名文件
--delay 秒数            延长爬行时间，默认三秒
-t  秒数                设定爬行超时时间，默认二十秒
-d                      对你提供的域名文件进行根域提取 处理并自动继续寻找注入点，可以配合-f参数
--path  sqlmap路径      指定sqlmap路径，例如/root/sqlmap/sqlmap.py
例子:
python wooscan.py -f urltest.txt      对urltest.txt文件内的域名进行测试
python wooscan.py -d -f urltest.txt  对urltest.txt内域名进行提取根域名处理，然后再开始测试

演示效果图：



![image](https://github.com/9tail123/wooscan/blob/master/image/-3c6bfdfcf1dba7f.jpg)
![image](https://github.com/9tail123/wooscan/blob/master/image/Screenshot_2018-03-26-17-56-59-994_com.sonelli.juicessh.png)


欢迎加我交流(☆_☆)


![☆dubaibai☆](https://github.com/9tail123/wooscan/blob/master/image/50f88e5a4d3c6e84.jpg)
