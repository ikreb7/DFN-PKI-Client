import base64
import datetime
from hashlib import sha1
from typing import Any, List

from suds import WebFault
from suds.client import Client

from dfn_pki_client import objects as obj
from dfn_pki_client.utils import get_wsdl


class PublicServicePKI:

    def __init__(self, config_path: str = 'config.ini', proxy: dict = {}):
        self.wsdl = get_wsdl('public', config_path)
        self.proxy = proxy
        self.client = Client(self.wsdl, proxy=self.proxy)

    def new_request(self, ra_id: int, pkcs10: Any, names: List, role: str, pin: str,
                    add_name: str, add_email: str, add_org_unit: str, publish: bool) -> int:
        """4.1.1 newRequest
        Args:
            ra_id (int): Nummer der RA, 0 für die Master-RA (RaID)
            pkcs10 (str): Der Zertifikatantrag im PEM-Format (PKCS10)
            names (List): Subject Alternative Names in der Form ("typ:wert", …) (AltNames)
            role (str): Die Rolle des beantragten Zertifikats (Role)
            pin (str): Das Sperrkennwort für das Zertifikat als SHA-1 Hash (Pin)
            add_name (str): Vollständiger Name des Antragstellers (AddName)
            add_email (str): E-Mail Adresse des Antragstellers (AddEMail)
            add_org_unit (str): Abteilung des Antragstellers (AddOrgUnit)
            publish (bool): Veröffentlichung des Zertifikats (Publish)

        Returns:
            serial (int): Die Seriennummer des hochgeladenen Antrags
        """

        alt_names = self.client.factory.create('ArrayOfString')
        alt_names._arrayType = "ns0:ArrayOfString"
        alt_names.item = ['DNS:{}'.format(url) for url in names]
        alt_names = ''

        pin = sha1(pin.encode()).hexdigest()

        try:
            new_request = self.client.service.newRequest(
                RaID=ra_id,
                PKCS10=pkcs10,
                AltNames=alt_names,
                Role=role,
                Pin=pin,
                AddName=add_name,
                AddEMail=add_email,
                AddOrgUnit=add_org_unit,
                Publish=publish
            )
        except WebFault as web_fault:
            print(f"Error: {web_fault}")
            new_request = None

        return new_request

    def new_revocation_request(self, ra_id: int, serial: int, reason: str, pin: str) -> int:
        """4.1.2 newRevocationRequest

        Args:
            ra_id (int): Nummer der RA, 0 für die Master-RA (RaID)
            serial (int): Die Seriennummer des Zertifikats (Serial)
            reason (str): Der Grund für die Sperrung (Reason)
            pin (str): Das Sperrkennwort für das Zertifikat als SHA-1 Hash (Pin)

        Returns:
            serial (int): Die Seriennummer des neuen Sperrantrags
        """

        pin = sha1(pin.encode()).hexdigest()

        return self.client.service.newRevocationRequest(ra_id, serial, reason, pin)

    def get_request_printout(self, ra_id: int, serial: int, pin: str, file: str = '') -> bytes:
        """4.1.3 getRequestPrintout
        Args:
            ra_id (int): Nummer der RA, 0 für die Master-RA (RaID)
            serial (int): Die Seriennummer des Zertifikatantrags
            # format (str): Rückgabeformat (Format)
            pin (str): Das Sperrkennwort für das Zertifikat als SHA-1 Hash (Pin)

        Returns:
            binary (bytes): Der Ausdruck des Zertifikatantrags

        """

        pin = sha1(pin.encode()).hexdigest()

        pdf = self.client.service.getRequestPrintout(ra_id, serial, 'application/pdf', pin)

        if not file:
            now = datetime.datetime.now()
            timestamp = now.strftime('%d_%m_%Y_%H_%M_%S')
            file = f"report_{timestamp}.pdf"

        with open(file, 'wb') as pdf_file:
            pdf_file.write(base64.b64decode(pdf))

        return pdf

    def get_certificate_by_request_serial(self, ra_id: int, serial: int, pin: str) -> str:
        """4.1.4 getCertificateByRequestSerial
        Args:
            ra_id (int): Nummer der RA, 0 für die Master-RA (RaID)
            serial (int): Die Seriennummer des Zertifikats (Serial)
            pin (str): Das Sperrkennwort für das Zertifikat als SHA-1 Hash

        Returns:
            cert (str): Das ausgestellte Zertifikat im PEM-Format

        """

        pin = sha1(pin.encode()).hexdigest()

        return self.client.service.getCertificateByRequestSerial(ra_id, serial, pin)

    def get_valid_domains(self, ra_id: int, type: str = '') -> List:
        """4.1.5 getValidDomains (RaID Type)
        Args:
            ra_id (int): Nummer der RA, 0 für die Master-RA (RaID)
            type (str): Domain-Typ: 'server' oder 'email' (Type)
        Returns:
            Liste mit Domain-Einträgen
        """
        if type:
            return self.client.service.getValidDomains(ra_id, type)
        else:
            return self.client.service.getValidDomains(ra_id)

    def get_request_info(self, ra_id: int, serial: int, pin: str) -> obj.DFNCERTTypesRequestInfo:
        """4.1.6 getRequestInfo
        args:
            ra_id (int): Nummer der RA (RaID)
            serial (int): Seriennummer des Zertifikatantrags (Serial)
            pin (str): SHA1 der Sperr-PIN des Zertifikatantrags (Hex-String) (Pin)

        Returns:
            Rückgabe: Struktur mit Informationen über den Antrag
        """

        res = self.client.service.getRequestInfo(ra_id, serial, pin)

        param = res.Parameters
        parameters = obj.DFNCERTTypesRequestParameters(param.RaID, param.Subject, param.SubjectAltNames, param.Role,
                                                       param.NotBefore, param.NotAfter, param.AdditionalName,
                                                       param.AdditionalEMail, param.AdditionalUnit)

        return obj.DFNCERTTypesRequestInfo(res.Serial, res.SameDNSerials, res.Status, parameters, res.PublicKey,
                                           res.PublicKeyAlgorithm, res.PublicKeyDigest, res.PublicKeyLength,
                                           res.Publish, res.SignatureAlgorithm, res.DateSubmitted, res.DateApproved,
                                           res.DateDeleted)

    def get_ca_info(self, ra_id: int) -> obj.DFNCERTypesCAInfo:
        """4.1.7 getCAInfo
        Args:
            ra_id (int): Nummer der RA

        Returns:
            Rückgabe: Struktur mit Informationen über die CA
        """

        res = self.client.service.getCAInfo(ra_id)
        ra_infos = res.RAInfos[0]
        ra_info = obj.DFNCERTypesRAInfo(ra_infos.ID, ra_infos.Name, ra_infos.DNPrefixes)
        return obj.DFNCERTypesCAInfo(res.RALoginID, ra_info, res.CAChain, res.Roles)
