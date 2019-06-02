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
        self._ps.headers['User-Agent'] = self._cfg.UA
        self.Ltpatoken2 = ""
        self.Authenticated = False
        pass
    

    def Authenticate(self):
        return self.Authenticated

        
