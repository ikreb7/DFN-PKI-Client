from typing import List, Union

from suds.client import Client

from dfn_pki_client import client_authentication
from dfn_pki_client import objects as obj
from dfn_pki_client.utils import get_wsdl


class RegistrationService:

    def __init__(self, config_path: str, proxy: dict = {}, pkcs12_byte_data: bytes = None, pkcs12_password: str = None):
        self.wsdl = get_wsdl('registration', config_path)
        print(config_path)
        self.proxy = proxy
        self.client = Client(self.wsdl,
                             transport=client_authentication.SudsTransport(proxy, config_path, pkcs12_byte_data,
                                                                           pkcs12_password))

    def get_ca_status(self) -> obj.DFNCERTTypesCAStatus:
        """5.1.1 getCAStatus

        Returns:
            Rückgabe (DFNCERTTypesCAStatus): Struktur mit Informationen über neue Elemente (tns:DFNCERTTypesCAStatus)
        """

        res = self.client.service.getCAStatus()
        return obj.DFNCERTTypesCAStatus(res.RequestNewCount, res.RevocationNewCount)

    def get_ca_info(self) -> obj.DFNCERTypesCAInfo:
        """5.1.2 getCAInfo

        Returns:
            Rückgabe (DFNCERTypesCAInfo): Struktur mit Informationen über die CA (tns:DFNCERTTypesCAInfo)
        """

        res = self.client.service.getCAInfo()
        ra_infos = []
        for info in res.RAInfos:
            info_id = info[2]
            info_name = info[1]
            info_dn_prefixes = info[0][0]
            ra_infos.append(obj.DFNCERTypesRAInfo(info_id, info_name, info_dn_prefixes))

        return obj.DFNCERTypesCAInfo(res.RALoginID, ra_infos, res.CAChain, res.Roles)

    def search_items_2(self, type: str, status: str, role: Union[str, None], desired_ra_id: Union[int, None],
                       last_serial: Union[int, None], limit: int) -> List[obj.DFNCERTTypesExtendedObjectInfo]:
        """5.1.3 searchItems2

        Args:
            type (str): Die Art der Einträge, die gesucht werden sollen
            status (str): Der Status der gesuchten Einträge
            role (str): Die Rolle der gesuchten Einträge. Darf 'null' sein, dann wird die Suche nicht nach der Rolle eingeschränkt.
            desired_ra_id (int): Die RA-ID, für die Einträge zurückgeliefert werden sollen. Darf 'null' sein, dann werden alle Einträge, für die der angemeldete RA-Operator eine Berechtigung hat, zurückgegeben.
            last_serial (int): Seriennummer, ab der die Suche fortgesetzt werden soll. Darf 'null' sein, dann wird bei der größten Seriennummer gestartet.
            limit (int): Die Anzahl der Einträge die zurückgeliefert werden sollen

        Returns:
            Liste von Informationsobjekten (List[DFNCERTTypesExtendedObjectInfo]) (tns:DFNCERTTypesExtendedObjectInfo[])

        # Type: [request | crr] -> Status: [NEW | PENDING | APPROVED | DELETED | ARCHIVED]
        # Type: certificate -> Status: [VALID, REVOKED]

        Diese Funktion ersetzt searchItems, searchExtendedItems, searchItemsByRole sowie searchItemsForRaID.
        """

        res = self.client.service.searchItems2(type, status, role, desired_ra_id, last_serial, limit)
        information_objects = []
        for r in res:
            not_before = r.NotBefore if hasattr(r, 'NotBefore') else None
            information_objects.append(obj.DFNCERTTypesExtendedObjectInfo(
                r.Serial, r.Subject, r.EMail, r.Role[0], r.Date, r.UnconfirmedEMails,
                r.RaID, r.AdditionalName, r.AdditionalEMail, r.AdditionalUnit, not_before
            ))
        return information_objects

    def get_request_data(self, serial: int) -> obj.DFNCERTTypesRequestData:
        """5.1.8 getRequestData

        Args:
            serial (int): Seriennummer des Zertifikatantrags (serial)

        Returns:
            Rückgabe (DFNCERTTypesRequestData): Struktur mit Informationen über den Zertifikatantrag (tns1:DFNCERTTypesRequestData)
        """

        res = self.client.service.getRequestData(serial)
        return obj.DFNCERTTypesRequestData(res.Serial, res.RaID, res.PKCS10,
                                           res.AltNames, res.Role, res.AddName,
                                           res.AddEMail, res.AddOrgUnit, res.Publish)

    def approve_request(self, serial: int, content: bytes, signature: str) -> bool:
        """5.2.1 approveRequest

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags
            content (byte): Der signierte Inhalt, Rückgabe von getRawRequest (xsd:base64Binary)
            signature (str): PKCS#7 mit Signatur über den Antrag im PEM-Format

        Returns:
            Rückgabe (bool): Bei Erfolg true
        """

        return self.client.service.approveRequest(serial, content, signature)

    def delete_request(self, serial: int) -> bool:
        """5.2.2 deleteRequest

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)

        Returns:
            Rückgabe (bool): Bei Erfolg true
        """

        return self.client.service.deleteRequest(serial)

    def renew_request(self, serial) -> int:
        """5.2.3 renewRequest

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags

        Returns:
            Rückgabe (int): Seriennummer des erneuerten Antrags
        """

        return self.client.service.renewRequest(serial)

    def renew_request_set_publish_if_needed(self, serial: int) -> obj.DFNCERTTypesRenewRequestResult:
        """5.2.4 renewRequestSetPublishIfNeeded

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)

        Returns:
            Rückgabe (DFNCERTTypesRenewRequestResult): Datenstruktur mit Angaben zum erneuerten Antrag (Tns1:DFNCERTTypesRenewRequestResult)
        """

        res = self.client.service.renewRequestSetPublishIfNeeded(serial)
        return obj.DFNCERTTypesRenewRequestResult(res.Serial, res.Server, res.Publish, res.HasChanged)

    def get_raw_request(self, serial: int) -> bytes:
        """5.2.5 getRawRequest

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)

        Returns:
            Rückgabe: Der komplette zu signierende Zertifikatantrag (xsd:base64Binary)
        """

        return self.client.service.getRawRequest(serial)

    def get_request_info(self, serial: int) -> obj.DFNCERTTypesRequestInfo:
        """5.2.6 getRequestInfo
        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)

        Returns:
            Rückgabe (DFNCERTTypesRequestInfo): Struktur mit Informationen über den Antrag (tns:DFNCERTTypesRequestInfo)
        """

        res = self.client.service.getRequestInfo(serial)
        return obj.DFNCERTTypesRequestInfo(
            res.Serial, res.SameDNSerials, res.Status, res.Parameters,
            res.PublicKey, res.PublicKeyAlgorithm, res.PublicKeyDigest,
            res.PublicKeyLength, res.Publish, res.SignatureAlgorithm,
            res.DateSubmitted, res.DateApproved, res.DateDeleted
        )

    def get_extended_request_info(self, serial: int) -> obj.DFNCERTTypesExtendedRequestInfo:
        """5.2.7 getExtendedRequestInfo

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)

        Returns:
            Rückgabe (DFNCERTTypesExtendedRequestInfo): Struktur mit Informationen über den Antrag (tns:DFNCERTTypesExtendedRequestInfo)
        """

        res = self.client.service.getExtendedRequestInfo(serial)
        return obj.DFNCERTTypesExtendedRequestInfo(
            res.Serial, res.SameDNSerials, res.Status, res.Parameters, res.PublicKey, res.PublicKeyAlgorithm,
            res.PublicKeyDigest, res.PublicKeyLength, res.Publish, res.SignatureAlgorithm, res.DateSubmitted,
            res.DateApproved, res.DateDeleted, res.SignerCertificateSerial, res.SignerCN
        )

    def get_request_printout(self, serial: int, format: str = 'application/pdf') -> bytes:
        """5.2.8 getRequestPrintout

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)
            format (str): Das gewünschte Format (MIME-Type) des Ausdrucks (Format)

        Returns:
            Rückgabe: Der Ausdruck des Zertifikatantrags (xsd:base64Binary)
        """

        return self.client.service.getRequestPrintout(serial, format)

    def set_request_parameters(self, serial: int, request_parameters) -> bool:
        """5.2.9 setRequestParameters

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)
            request_parameters: Eine Struktur mit gewünschten Werten

        Returns:
            Rückgabe (bool): Bei Erfolg true
        """

        return self.client.service.setRequestParameters(serial, request_parameters)

    def set_extended_request_parameters(self, serial: int, request_parameters) -> bool:
        """5.2.10 setExtendedRequestParameters

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)
            request_parameters: Eine Struktur mit gewünschten Werten

        Returns:
            Rückgabe (bool): Bei Erfolg true
        """

        return self.client.service.setRequestParameters(serial, request_parameters)

    def send_confirmation_email(self, serial, emails: List) -> bool:
        """5.2.11 sendConfirmationEMail

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags (Serial)
            emails (List[str]): Liste mit E-Mail-Adressen, an die eine Bestätigungs-E-Mail versendet werden soll

        Returns:
            Rückgabe (bool): Bei Erfolg true
        """

        return self.client.service.sendConfirmationEMail(serial, emails)

    def get_certificate(self, serial: int) -> str:
        """5.3.1 getCertificate

        Args:
            serial (int): Die Seriennummer des Zertifikats

        Returns:
            Rückgabe (str): Das gewünschte Zertifikat im PEM-Format
        """
        return self.client.service.getCertificate(serial)

    def get_certificate_by_request_serial(self, serial: int) -> str:
        """5.3.2 getCertificateByRequestSerial

        Args:
            serial (int): Die Seriennummer des Zertifikatantrags

        Returns:
            Rückgabe (str): Das gewünschte Zertifikat im PEM-Format
        """

        return self.client.service.getCertificateByRequestSerial(serial)

    def get_certificate_info(self, serial: int) -> obj.DFNCERTTypesCertificateInfo:
        """5.3.3 getCertificateInfo

        Args:
            serial (int): Die Seriennummer des Zertifikats

        Returns:
            Rückgabe (DFNCERTTypesCertificateInfo): Meta-Informationen über das Zertifikat
        """

        res = self.client.service.getCertificateInfo(serial)
        return obj.DFNCERTTypesCertificateInfo(res.RequestSerial, res.Publish, res.Role, res.Status, res.PEM)

    def new_revocation_request(self, serial: int, reason: str) -> int:
        """5.4.1 newRevocationRequest

        Args:
            serial (int): Die Seriennummer des Zertifikats
            reason (str): Der Gurnd für die Speerung

        Returns:
            Rückgabe (int): Die Seriennummer des neuen Sperrantrags
        """

        return self.client.service.newRevocationRequest(serial, reason)

    def approve_revocation_request(self, serial: int, content: bytes, signature: str) -> bool:
        """5.4.2 approveRevocationRequest

        Args:
            serial (int): Die Seriennummer des Sperrantrags
            content (bytes): Rückgabewert von getRawRevocationRequest
            signature (str): PKCS#7 Signatur über den Sperrantrag

        Returns:
            Rückgabe (bool): Bei Erfolg true
        """

        return self.client.service.approveRevocationRequest(serial, content, signature)

    def get_raw_revocation_request(self, serial: int) -> bytes:
        """5.4.3 getRawRevocationRequest

        Args:
            serial (int): Die Seriennummer des Sperrantrags

        Returns:
            Rückgabe (bytes): Sperrantrag aus der Datenbank der CA
        """

        return self.client.service.getRawRevocationRequest(serial)

    def get_revocation_info(self, serial: int) -> obj.DFNCERTTypesRevocationInfo:
        """5.4.4 getRevocationInfo

        Args:
            serial (int): Die Seriennummer des Sperrantrags

        Returns:
            Rückgabe (DFNCERTTypesRevocationInfo):
        """

        res = self.client.service.getRevocationInfo(serial)
        return obj.DFNCERTTypesRevocationInfo(res.Status, res.Serial, res.CertificateSerial, res.RaID,
                                              res.DateSubmitted, res.DateApproved, res.DateDeleted,
                                              res.Parameters)
