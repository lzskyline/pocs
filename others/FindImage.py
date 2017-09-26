import re
import urlparse
from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register

class TestPOC(POCBase):
    appName='CTF'
    name='FindImage'
    vulID='00000'
    version='1.0'
    author='LzSkyline'
    vulDate='0000-00-00'
    createDate='2017-09-25'
    updateDate='2017-09-25'
    references=['https://www.seebug.org/vuldb/ssvid-00000']
    appPowerLink='https://www.lzskyline.com'
    appVersion='0.0.0'
    vulType='Others'
    desc='https://www.seebug.org/'
    samples=['http://chinalover.sinaapp.com/web2/']
    def _attack(self):
        result={}
        vulurl=self.url
        payload=""
        param={}
        resp=req.get(vulurl,params=param)
        match_result=re.search(r'<img.*src=[\"|\']([^\"|^\']*)([\"|\']).*>',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['ImageUrl']=self.url + match_result.group(1)
        return self.parse_attack(result)
    
    def _verify(self):
        result={}
        vulurl=self.url
        payload=""
        param={}
        resp=req.get(vulurl,params=param)
        if "<img " in resp.content:
            result['VerifyInfo']={}
            result['VerifyInfo']['URL']=vulurl
            result['VerifyInfo']['HasImage']="Yes"
        return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

        
register(TestPOC)
        
