#!env pyton3

import requests
import logging
import pdb
import re

class PGUAuthenticator:
    """ PGU Authenticator """
    def __init__(self, cfg):
        self._ps = requests.Session()
        self._cfg = cfg
        self._ps.headers['User-Agent'] = self._cfg["UserAgent"]
        pass
    

    """
    Аутентификация.
    Входные параметры: 
    URL - редирект-урл от подсистемы.
    вид: https://esia.gosuslugi.ru/aas/oauth2/ac? client_id=xx & client_secret= xx ..
    & response_type=code

    referer: куда должно вернуться после аутентификации

    возвращает: url для вызова на подсистеме для завершения аутентификации
    имеет вид ...?code = xxx
    зависит от вызывающей подсистемы
    """
    def AuthenticateByEmail(self,url,referer):
        r_ac = self._ps.get(url,allow_redirects=False, 
                headers={"referer":referer})
        meta_redir = re.search('<meta http-equiv="refresh" content="0;url=([^"]*)">',r_ac.text) 
        r_SSO = self._ps.get(meta_redir.group(1), cookies=r_ac.cookies, allow_redirects=False)
        if r_SSO.status_code != 302:
            logging.error("Церемония поменялась")
            raise

        AuthnEngine_cookies={
                '_idp_authn_lc_key' : r_SSO.cookies['_idp_authn_lc_key'],
                'idp_id':r_SSO.cookies['idp_id'],
                'JSESSIONID':r_ac.cookies['JSESSIONID'] }

        r_AuthnEngine=self._ps.get(r_SSO.headers["Location"], allow_redirects=False,
                cookies=AuthnEngine_cookies)

        command=re.search("LoginViewModel\('/idp','','(.*)','','null','null',false, 300, 'gosuslugi.ru'\);",
                r_AuthnEngine.text )


        #pdb.set_trace()
        login_data={
                "mobileOrEmail":self._cfg["login"],
                "snils":"",
                "password":self._cfg["password"],
                "login":self._cfg["login"],
                "command":command.group(1),
                "idType":"email" }

        pwd_cookies={
                '_idp_authn_id': 'email:'+self._cfg["login"],
                '_idp_authn_lc_key':r_SSO.cookies['_idp_authn_lc_key'],
                'idp_id':r_AuthnEngine.cookies['idp_id'],
                'SCS':r_AuthnEngine.cookies['SCS'],
                'JSESSIONID':r_ac.cookies['JSESSIONID'],
                'login_value':self._cfg["login"],
                'oiosaml-fragment':'',
                'timezone':'3',
                'userSelectedLanguage':'ru'}

        #pdb.set_trace()
        r_pwddo=self._ps.post("https://esia.gosuslugi.ru/idp/login/pwd/do", 
                data=login_data, 
                headers={"referer":"https://esia.gosuslugi.ru/idp/rlogin?cc=bp"},
                cookies=pwd_cookies,
                allow_redirects=False)
        if r_pwddo.status_code !=302 :
            print("Церемония поменялась")

        SSO2_cookies={
                '_idp_authn_id': 'email:'+self._cfg["login"],
                '_idp_authn_lc_key':r_SSO.cookies['_idp_authn_lc_key'],
                '_idp_session':r_pwddo.cookies['_idp_session'],
                'idp_id':r_AuthnEngine.cookies['idp_id'],
                'SCS':r_AuthnEngine.cookies['SCS'],
                'JSESSIONID':r_ac.cookies['JSESSIONID'],
                'login_value':self._cfg["login"],
                'oiosaml-fragment':'',
                'timezone':'3',
                'userSelectedLanguage':'ru'}

        r_SSO2=self._ps.get(r_pwddo.headers['Location'],
                allow_redirects=False,
                headers={"referer":"https://esia.gosuslugi.ru/idp/rlogin?cc=bp"},
                cookies=SSO2_cookies)

        samlr=re.search('<input type="hidden" name="SAMLResponse" value="(.*)"/>',r_SSO2.text)

        SAMLResponse=samlr.group(1)

        post_data={
                'RelayState':re.search('RelayState=([-_a-z0-9]*)',meta_redir.group(1)).group(1),
                'SAMLResponse':SAMLResponse}
        consumer_cookies={
                '_idp_authn_id': 'email:'+self._cfg["login"],
                'bs':r_pwddo.cookies['bs'],
                'idp_id':r_AuthnEngine.cookies['idp_id'],
                'SCS':r_AuthnEngine.cookies['SCS'],
                'JSESSIONID':r_ac.cookies['JSESSIONID'],
                'login_value':self._cfg["login"],
                'oauth_id':r_ac.cookies['oauth_id'],
                'oiosaml-fragment':'',
                'timezone':'3',
                'userSelectedLanguage':'ru'}

        r_SAMLAC=self._ps.post("https://esia.gosuslugi.ru/aas/oauth2/saml/SAMLAssertionConsumer",
                data=post_data,
                allow_redirects=False,
                headers={'referer':'https://esia.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO'},
                cookies=consumer_cookies)

        if r_SAMLAC.status_code !=302 :
            logging.error("Церемония поменялась")
            raise
        #pdb.set_trace()

        self._ps.cookies.clear()
        r_acfinish=self._ps.get(r_SAMLAC.headers['location'],
                allow_redirects=False,
                headers={'referer':'https://esia.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO'},
                cookies=consumer_cookies)

        if r_acfinish.status_code !=302 :
            logging.error("Церемония поменялась")
            raise

        #pdb.set_trace()
        #callback_cookies={
        #        'fm': r_ae.cookies['fm'],
        #        'history': r_execute.cookies['history'],
        #        'lstate' : r_execute.cookies['lstate'],
        #        'oauth_az':r_ae.cookies['oauth_az'],
        #        'origin': r_ae.cookies['origin']}

        #r_callback=ps.get(r_acfinish.headers['location'],allow_redirects=False,
        #        cookies=callback_cookies,
        #        headers={'referer':'https://esia.gosuslugi.ru/'})

        #self.Ltpatoken2 = r_callback.cookies['Ltpatoken2']
        #self.Authenticated = self.Ltpatoken2 != ""

        return r_acfinish.headers['location']
        
