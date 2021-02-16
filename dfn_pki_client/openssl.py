from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class OpenSSL:

    def __init__(self):
        pass

    @staticmethod
    def create_csr(file_name: str = 'DFN-PKI-Client.key', password: str = '') -> str:

        # create public and private key
        # https://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                               backend=default_backend())

        if password:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b'password')
            )
        else:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

        with open(file_name, 'wb') as pk_file:
            pk_file.write(pem)

        # create Zertifikatsrequest (CSR)
        subject = {'country_name': u'DE',
                   'state_name': u'Bundesland',
                   'locality_name': u'Stadt',
                   'organization_name': u'Testinstallation Eins CA',
                   'common_name': u'TestUser'}

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, subject['country_name']),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject['state_name']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, subject['locality_name']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject['organization_name']),
                x509.NameAttribute(NameOID.COMMON_NAME, subject['common_name']),
            ])).add_extension(
            x509.SubjectAlternativeName([]),
            critical=False
        ).sign(private_key, hashes.SHA256(), backend=default_backend())

        with open('DFN-PKI-Client_csr.pem', 'wb') as csr_file:
            csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

        pkcs10 = csr.public_bytes(serialization.Encoding.PEM).decode()

        return pkcs10
