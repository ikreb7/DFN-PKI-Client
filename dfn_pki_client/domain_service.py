import configparser
import sys
import urllib

from ssl import PROTOCOL_TLS as ssl_protocol
from typing import List

from OpenSSL.crypto import load_pkcs12
from suds.client import Client
from suds.transport.http import HttpTransport
from urllib3.contrib.pyopenssl import PyOpenSSLContext

from dfn_pki_client import objects as obj
from dfn_pki_client.utils import get_wsdl
from dfn_pki_client.client_authentication import SudsTransport


class DomainService:

    def __init__(self, config_path: str = 'config.ini', proxy: dict = {}, pkcs12_byte_data: bytes = None,
                 pkcs12_password: str = ""):
        self.wsdl = get_wsdl('domain', config_path)
        self.proxy = proxy
        self.client = Client(self.wsdl, transport=SudsTransport(self.proxy, config_path, pkcs12_byte_data,
                                                                pkcs12_password))

    def delete_domain(self, ra_id: int, name: str, type: str, change: str) -> str:
        """5.5.4 deleteDomain

        Args:
            ra_id (int): Die RA des Domain-Namen, der gelöscht werden soll
            name (str): Name des zu löschenden Domain-Eintrags
            type (str): Typ des Domain-Eintrags (server[-host] oder email[-host])
            change (str): Letzte Änderungsprüfsumme

        Returns:
            Rückgabe (str): Aktuelle Änderungsprüfsumme
        """

        return self.client.service.deleteDomain(ra_id, name, type, change)

    def delete_domain2(self, ra_id: int, name: str, type: str, change: str) -> obj.DFNCERTTypesDeleteDomain2Result:
        """5.5.5 deleteDomain2

        Args:
            ra_id (int): Die RA des Domain-Namen, der gelöscht werden soll
            name (str): Name des zu löschenden Domain-Eintrags
            type (str): Typ des Domain-Eintrags (server[-host] oder email[-host])
            change (str): Letzte Änderungsprüfsumme

        Returns:
            Rückgabe (DFNCERTTypesDeleteDomain2Result): Aktuelle Änderungsprüfsumme und ggf. Liste der gültigen Zertifikate zu diesem Domain-Namen.
        """

        res = self.client.service.deleteDomain2(ra_id, name, type, change)
        return obj.DFNCERTTypesDeleteDomain2Result(res.Result, res.CertInfos)

    def get_tlds(self) -> obj.DFNCERTTypesTLDs:
        """5.5.6 getTLDs

        Returns:
            Rückgabe (DFNCERTTypesTLDs): Liste der Top-level-domains
        """

        res = self.client.service.getTLDs()
        return obj.DFNCERTTypesTLDs(res.TLDs)

    def get_certificates_for_domain(self, ra_id: int, name: str, type: str, status: str) -> List[obj.DFNCERTTypesShortCertInfo]:
        """5.5.7 getCertificatesForDomain

        Args:
            ra_id (int): Die RA des Domain-Namen (RaID)
            name (str): Domain-Name (Name)
            type (str): Typ des Domain-Eintrags (server[-host] oder email[-host]) (Type)
            status (str): Status der Zertifikate ('VALID' oder 'REVOKED') (Status)

        Returns:
            Rückgabe (List[DFNCERTTypesShortCertInfo]): Liste der gültigen Zertifikate zu diesem Domain-Namen.
        """

        res = self.client.service.getCertificatesForDomain(ra_id, name, type, status)
        short_cert_info = []
        for r in res:
            short_cert_info.append(obj.DFNCERTTypesShortCertInfo(r.RaID, r.Serial, r.SubjectDN, r.NotAfter))
        return short_cert_info

    def get_validation_parameter(self, name: str) -> List[obj.DFNCERTTypesValidationParameter]:
        """5.5.8 getValidationParameter

        Args:
            name (str): Domain-Name

        Returns:
            Rückgabe (List[DFNCERTTypesValidationParameter]): Liste der möglichen Validierungs-Parameter für die angefragte Domain.

        """

        res = self.client.service.getValidationParameter(name)
        print(res)
        validation_parameter = []
        for r in res:
            name = r.Name if hasattr(r, 'Name') else ''
            email = r.EMail if hasattr(r, 'EMail') else ''
            adns = r.ADNs if hasattr(r, 'ADNs') else ''
            validation_parameter.append(obj.DFNCERTTypesValidationParameter(name, r.Method, email, adns))
        return validation_parameter

    def list_domains(self, ra_id: int) -> obj.DFNCERTTypesDomainListResult:
        """5.5.1 listDomains

         Args:
             ra_id (int): Die RA deren Domain-Namen gelistet werden sollen

        Returns:
            Rückgabe (DFNCERTTypesDomainListResult): Alle Domain-Einträge und die Zugriffsrechte der angeforderten RA
        """

        res = self.client.service.listDomains(ra_id)
        results = []
        for result in res.Result:
            results.append(obj.DFNCERTTypesDomain(result.Name, result.Type, result.Secret,
                                                  result.Approved, result.ApprovedDate))
        acl = obj.DFNCERTTypesDomainACL(res.ACL.RaID, res.ACL.Allowed)
        return obj.DFNCERTTypesDomainListResult(res.Change, results, acl)

    def list_extended_domains(self, ra_id: int) -> obj.DFNCERTTypesExtendedDomainListResult:
        """5.5.2 listExtendedDomains

        Args:
            ra_id (int): Die RA, deren Domain-Namen gelistet werden sollen

        Returns:
            Rückgabe (DFNCERTTypesExtendedDomainListResult): Alle Domain-Einträge und die Zugriffsrechte der angeforderten RA
        """

        res = self.client.service.listExtendedDomains(ra_id)
        print(res)
        results = []
        for result in res.Result:
            results.append(obj.DFNCERTTypesDomain(result.Name, result.Type, result.Secret,
                                                  result.Approved, result.ApprovedDate))
        acl = obj.DFNCERTTypesDomainACL(res.ACL.RaID, res.ACL.Allowed)
        return obj.DFNCERTTypesExtendedDomainListResult(results, acl)

    def request_domain(self, ra_id: int, name: str, type: str, public: bool, change: str) -> str:
        """5.5.3 requestDomain

        Args:
            ra_id (int): Die RA in der ein Domain-Name beantragt werden sollen
            name (str): Beantragter Domain-Name
            type (str): Typ des Domain-Eintrags (server[-host] oder email[-host])
            public (bool): Sichtbar auf den Antragsseiten
            change (str): Aktuelle Änderungsprüfsumme

        Returns:
            Rückgabe (str): Neue Änderungsprüfsumme

        values of type:
            server: Es wird ein Domain-Name für Server beantragt. Es sollen alle Hostnamen inklusive Subdomains vor diesem Namen erlaubt sein.
            server-host: Es wird genau ein FQDN für Serverzertifikate erlaubt.
            email: Es wird ein Domain-Name für EMail-Adressen beantragt. Es sind alle Adressen vor dieser Domain und beliebige Subdomains zugelassen. Beispiel: Eingetragen wird „dfn.de“. Gültige Adressen sind dann „pki@dfn.de“ sowie „pki@pca.dfn.de“.
            email-host: Es wird genau eine Domain für EMail-Adressen beantragt. Es sind beliebige EMail-Adressen aber keine beliebigen Subdomains erlaubt.
        """

        return self.client.service.requestDomain(ra_id, name, type, public, change)

    def set_validation_parameter(self, ra_id: int, name: str, type: str, method: str,
                                 email_local: str, email_domain: str, change: str) -> str:
        """5.5.9 setValidationParameter

        Args:
            ra_id (int): RA-ID des Domain-Eintrags
            name (str): Domain-Name
            type (str): Typ (server, server-host)
            method (str): Prüfmethode (2-Domain-Contact-Mail-SOA, 2-Domain-Contact-Mail-Whois, 4-Constructed-Mail)
            email_local (str): Lokaler Part der E-Mail-Adresse, an die eine Challenge-E-Mail versendet werden soll.
            email_domain (str): Domain Part der E-Mail-Adresse, an die eine Challenge-E-Mail versendet werden soll.
            change (str): Letzte Änderungsprüfsumme

        Returns:
            Rückgabe (str): Aktuelle Änderungsprüfsumme
        """

        return self.client.service.setValidationParameter(ra_id, name, type, method, email_local, email_domain, change)

    def send_challenge_email(self, ra_id: int, name: str, type: str, change: str) -> obj.DFNCERTTypesSendChallengeEMailResult:
        """5.5.10 sendChallengeEMail

        Args:
            ra_id (int): RA-ID des Domain-Eintrags
            name (str): Domain-Name
            type (str): Typ (server, server-host)
            change (str): Letzte Änderungsprüfsumme

        Returns:
            Rückgabe (DFNCERTTypesSendChallengeEMailResult): Struktur, die die aktualle Änderungsprüfsumme sowie das Datum, an dem die Challenge-E-Mail versendet wurde, enthält.
        """

        res = self.client.service.sendChallengeEMail(ra_id, name, type, change)
        return obj.DFNCERTTypesSendChallengeEMailResult(res.Change, res.LastChallengeEMailSent)
