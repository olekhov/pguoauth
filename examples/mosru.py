#!env python3.7
"""
Пример использования модуля аутентификации на портале Госуслуг
для получения доступа к личному кабинету на сайте госуслуг г. Москвы
https://pgu.mos.ru
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname( __file__ ), "..", "pguoauth"))
from pguoauth import PGUAuthenticator

import json
import logging
import requests
import re
import pdb
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("chardet").setLevel(logging.WARNING)

with open('config.json') as json_data_file:
    pguconfig = json.load(json_data_file)

au = PGUAuthenticator(pguconfig)
ps=requests.Session()
popular="https://www.mos.ru/services/catalog/popular/"

logging.debug("Открываем портал www.mos.ru")
r_ae=ps.get("https://login.mos.ru/sps/oauth/ae?client_id=Wiu8G6vfDssAMOeyzf76&response_type=code&redirect_uri=https://my.mos.ru/my/website_redirect_uri&scope=openid+profile", allow_redirects=False)
if r_ae.status_code != 303 or r_ae.headers['Location']!="/sps/login/methods/password":
    logging.error("Церемония поменялась")
    raise
#ps.cookies.update(r.cookies)
r_password=ps.get("https://login.mos.ru"+r_ae.headers['Location'], allow_redirects=False)
logging.debug("Начало аутентификационной сессии")
r_opts=ps.get("https://www.mos.ru/api/oauth20/v1/frontend/json/ru/options", headers={"referer":popular})
logging.debug("Вход")
r_enter=ps.get(f"https://www.mos.ru/api/oauth20/v1/frontend/json/ru/process/enter?redirect={popular}",
        cookies=r_opts.cookies, allow_redirects=False)

if r_enter.status_code !=302:
    logging.error("Церемония поменялась")
    raise
r_authorize=ps.get(r_enter.headers['Location'], allow_redirects=False)
logging.debug("Переход на форму авторизации")
if r_enter.status_code !=302:
    logging.error("Церемония поменялась")
    raise

#ps.cookies.update(r_password.cookies)
#ps.cookies.update(r.cookies)
r_ae2=ps.get(r_authorize.headers['Location'], allow_redirects=False)

if r_ae2.status_code !=303 or r_ae2.headers['Location']!="/sps/login/methods/password":
    logging.error("Церемония поменялась")
    raise

r_password2=ps.get("https://login.mos.ru"+r_ae2.headers['Location'], allow_redirects=False, cookies=r_ae2.cookies)
if r_password2.status_code != 200 :
    logging.error("Церемония поменялась")
    raise

logging.debug("Выбираем вариант входа: через госуслуги")

r_execute=ps.get("https://login.mos.ru/sps/login/externalIdps/execute?typ=esia&name=esia_1&isPopup=false",
        headers={"referer": "https://login.mos.ru/sps/login/methods/password"}, 
        cookies=r_ae2.cookies, allow_redirects=False)

if r_execute.status_code !=303 :
    logging.error("Церемония поменялась")
    raise

esia_request=r_execute.headers["Location"]
code=au.AuthenticateByEmail(esia_request, "https://login.mos.ru")

# в code должен быть хороший ответ типа 
# https://login.mos.ru/sps/login/externalIdps/callback/esia/esia_1/false?c
# ode=eyJ2ZXIiOjEsInR5cCI6IkpXVCIsInNidCI6ImF1dGhvcml6YXRpb25fY29...

callback_cookies={
        'fm': r_ae.cookies['fm'],
        'history': r_execute.cookies['history'],
        'lstate' : r_execute.cookies['lstate'],
        'oauth_az':r_ae.cookies['oauth_az'],
        'origin': r_ae.cookies['origin']}


r_callback = ps.get(code, allow_redirects=False, 
        cookies=callback_cookies,
        headers={'referer':'https://esia.gosuslugi.ru/'})
if r_callback.cookies['Ltpatoken2'] != '' :
    print("Авторизовано успешно")


