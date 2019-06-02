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


with open('config.json') as json_data_file:
    data = json.load(json_data_file)
    print(data)
