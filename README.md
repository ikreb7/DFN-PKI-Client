# DFN-PKI-Client

## Example

```
#!/usr/bin/env python

from public_service import PublicServicePKI
from registration_service import RegistrationService
from utils import get_wsdl


def main():

    pki = PublicServicePKI('config.ini')

    ca_info = p.get_ca_info(42)

    print(ca_info)


if __name__ == '__main__':
    main()

```

## Installation

### Linux (e.g. Ubuntu)

    apt install openssl rustc
    pip3 install cryptography pyopenssl suds-community urllib3

### macOS

    brew install openssl swig rustup
    pip3 install cryptography pyopenssl suds-community urllib3

### Windows (untested)

    pip3 install cryptography pyopenssl suds-community urllib3


## Setup

Create thr file ``config.ini``

```
[default]
cert = file_name.p12
password = 0123456789
public_wsdl = https://pki.pca.dfn.de/<ca_name>/cgi-bin/pub/soap?wsdl=1
registration_wsdl = https://ra.pca.dfn.de/<ca_name>/cgi-bin/ra/soap?wsdl=1
domain_wsdl = https://ra.pca.dfn.de/<ca_name>/cgi-bin/ra/soap/DFNCERT/Domains?wsdl=1'
```
