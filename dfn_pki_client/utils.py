import configparser
import pathlib
import sys
import typing

from OpenSSL.crypto import load_pkcs12
from ssl import PROTOCOL_TLS as ssl_protocol
from urllib3.contrib.pyopenssl import PyOpenSSLContext


def get_wsdl(wsdl: str, config_path: str = 'config.ini', section: str = 'default') -> typing.Optional[str]:
    config = configparser.ConfigParser()
    path = pathlib.Path(config_path)
    if path.exists():
        config.read(path)

        if section in config:
            if config[section][f"{wsdl}_wsdl"]:
                return config[section][f"{wsdl}_wsdl"]
            else:
                print(f"WSDL entry {wsdl} is missing.")
                sys.exit(-1)
        else:
            print(f"Section {section} in config.ini is missing.")
            sys.exit(-1)
    else:
        print(f"File {path} doesn't exist.")
        sys.exit(-1)


def gen_ssl_context(config_path: str, section: str = 'default'):
    config = configparser.ConfigParser()

    path = pathlib.Path(config_path)
    if not path.exists():
        print(f"File {path} doesn't exist.")
        sys.exit(-1)

    config.read(path)

    if section in config:
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
    else:
        print(f"Section {section} in config.ini is missing.")
        sys.exit(-1)

    with open(cert_name, 'rb') as pkcs12_file:
        pkcs12_data = pkcs12_file.read()

    if isinstance(password, bytes):
        pkcs12_password_bytes = password
    else:
        pkcs12_password_bytes = password.encode('utf8')

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
