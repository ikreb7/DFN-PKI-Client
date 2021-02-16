import configparser
import pathlib
import sys
import urllib
from ssl import PROTOCOL_TLS as ssl_protocol
from typing import Tuple

from OpenSSL.crypto import load_pkcs12
from suds.transport.http import HttpTransport
from urllib3.contrib.pyopenssl import PyOpenSSLContext


class SudsTransport(HttpTransport):
    def __init__(self, proxy=None, section: str = 'default'):
        self.section = section
        self.cert_name, self.password = self.get_cert_password(self.section)
        self.proxy = proxy
        self.context = self.create_pyopenssl_sslcontext()
        super(SudsTransport, self).__init__(proxy=self.proxy)

    @staticmethod
    def get_cert_password(section: str, config_path: str = 'config.ini') -> Tuple[str, str]:

        path = pathlib.Path(config_path)
        if not path.exists():
            print(f"File {path} doesn't exist.")
            sys.exit(-1)

        config = configparser.ConfigParser()
        config_exists = config.read(config_path)
        if config_exists:
            if section in config.sections():
                if config[section]['cert']:
                    cert_name = config[section]['cert']
                else:
                    print('Certfile is missing.')
                    sys.exit(-1)
                if config[section]['password']:
                    password = config[section]['password']
                else:
                    print('Password is missing.')
                    sys.exit(-1)
                return cert_name, password
            else:
                print(f"Section '{section}' in config.ini is missing.")
                sys.exit(-1)
        else:
            print(f"File {config_path} not found or is empty.")
            sys.exit(-1)

    def u2handlers(self):
        handlers = super(SudsTransport, self).u2handlers()
        handlers.append(urllib.request.HTTPSHandler(context=self.context))
        handlers.append(urllib.request.ProxyHandler(proxies=self.proxy))
        return handlers

    def create_pyopenssl_sslcontext(self):
        with open(self.cert_name, 'rb') as pkcs12_file:
            pkcs12_data = pkcs12_file.read()

        if isinstance(self.password, bytes):
            pkcs12_password_bytes = self.password
        else:
            pkcs12_password_bytes = self.password.encode('utf8')

        p12 = load_pkcs12(pkcs12_data, pkcs12_password_bytes)
        cert = p12.get_certificate()

        ssl_context = PyOpenSSLContext(ssl_protocol)
        ssl_context._ctx.use_certificate(cert)

        ca_certs = p12.get_ca_certificates()
        if ca_certs:
            for ca_cert in ca_certs:
                ssl_context._ctx.add_extra_chain_cert(ca_cert)
        ssl_context._ctx.use_privatekey(p12.get_privatekey())

        return ssl_context
