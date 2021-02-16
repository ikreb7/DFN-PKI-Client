from dataclasses import dataclass
from typing import List

from suds.sax.date import DateTime
from suds.sax.text import Text


@dataclass
class DFNCERTTypesCAStatus:
    """6.1.1 DFNCERTTypesCAStatus

    Attributes:
        request_new_count (int): Anzahl der neuen Zertifikatanträge (RequestNewCount)
        revocation_new_count (int): Anzahl der neuen Sperranträge (RevocationNewCount)
    """
    request_new_count: int
    revocation_new_count: int


@dataclass
class DFNCERTypesRAInfo:
    """6.1.3 DFNCERTypesRAInfo

    Attributes:
        id (int): RA-Nummer des Eintrags (ID)
        name (str): Installationsname der CA (Name)
        dn_prefixes (List[Text]): Liste mit allen erlaubten Namensräumen (DNPrefixes)
    """
    id: int
    name: str
    dn_prefixes: List[Text]


@dataclass
class DFNCERTypesCAInfo:
    """6.1.2 DFNCERTypesCAInfo

    Attributes:
        ra_login_id (int): RA_ID des Clients nach Authentifizierung (RALoginID)
        ra_infos (DFNCERTypesRAInfo): Liste mit Informationen über alle zu dieser CA gehörenden Registrierungsstellen (RAInfos)
        ca_chain (str): Das aktuelle CA-Zertifikat und Kette im PEM-Format (CAChain)
        roles (str): Liste mit allen von dieser CA unterstützten Rollen-Namen (Roles)
    """
    ra_login_id: int
    ra_infos: List[DFNCERTypesRAInfo]
    ca_chain: str
    roles: str


@dataclass
class DFNCERTTypesCertificateInfo:
    """6.2.1 DFNCERTTypesCertificateInfo

    Attributes:
        request_serial (int): Seriennummer des passenden Requests zu diesem Zertifikat (RequestSerial)
        publish (bool): Wurde das Zertifikat veröffentlicht? (Publish)
        role (str): Die Rolle des Zertifikats in der CA (Role)
        status (str): Der Status des Zertifikats (VALID oder REVOKED) (Status)
        pem (str): Das Zertifikat im PEM-Format (PEM)
    """
    request_serial: int
    publish: bool
    role: str
    status: str
    pem: str


@dataclass
class DFNCERTTypesShortCertInfo:
    """6.2.2 DFNCERTTypesShortCertInfo

    Attributes:
        ra_id (int): RA-Nummer des Zertifikats (RaID)
        serial (int): Seriennummer des Zertifikats (Serial)
        subject_dn (str): Der Subject-DN des Zertifikats (SubjectDN)
        not_after (DateTime): Das Ablaufdatum des Zertifikats („gültig bis“, Zeitzone: UTC) (NotAfter) (xsd:dateTime)

    """
    ra_id: int
    serial: int
    subject_dn: str
    not_after: DateTime


@dataclass
class DFNCERTTypesObjectInfo:
    """6.2.3 DFNCERTTypesObjectInfo

    Attributes:
        serial (int): Seriennummer des Eintrags (Serial)
        subject (str): Subject-DN des Eintrags (Subject)
        email (str): E-Mail Adresse entweder aus Subject-DN, wenn dort nicht vorhanden aus AdditionalEmail (EMail)
        role (str): Beantragte Rolle des Eintrags (Role)
        date (DateTime): Für Anträge Datum des Eingangs und für Zertifikate NotAfter (entspricht "gültig bis", Zeitzone: UTC) (xsd:dateTime)
    """
    serial: int
    subject: str
    email: str
    role: str
    date: DateTime


@dataclass
class DFNCERTTypesExtendedObjectInfo:
    """6.2.4 DFNCERTTypesExtendedObjectInfo

    Attributes:
        serial (int): Seriennummer des Eintrags (Serial)
        subject (str): Subject-DN des Eintrags (Subject)
        email (str): E-Mail Adresse entweder aus Subject-DN, wenn dort nicht vorhanden aus AdditionalEmail (EMail)
        role (str): Beantragte Rolle des Eintrags (Role)
        date (DateTime): Für Anträge Datum des Eingangs und für Zertifikate NotAfter (entspricht "gültig bis", Zeitzone: UTC) (xsd:dateTime) (Date)
        unconfirmed_emails (int): Anzahl der noch nicht bestätigten E-Mail-Adressen (UnconfirmedEMails)
        ra_id (int): RA Nummer des Eintrags (RaID)
        additional_name (str): Name des Antragsstellers (AdditionalName)
        additional_email (str): Kontakt-E-Mail-Adresse des Antragsstellers (AdditionalEMail)
        additional_org_unit (str): Abteilung des Antragsstellers (AdditionalOrgUnit)
        not_before (DateTime): Gültigkeitsbeginn des Zertifikats (Zeitzone: UTC) (NotBefore) (xsd:dateTime)
    """
    serial: int
    subject: str
    email: str
    role: str
    date: DateTime
    unconfirmed_emails: int
    ra_id: int
    additional_name: str
    additional_email: str
    additional_org_unit: str
    not_before: DateTime = None


@dataclass
class DFNCERTTypesRequestParameters:
    """6.3.1 DFNCERTTypesRequestParameters

    Attributes:
        ra_id (int): RA Nummer des Antrags (RaID)
        subject (str): Subject DN des Antrags (Subject)
        subject_alt_names (List[str]): Subject Alternative Names als Array von Strings. Format ist: ("typ:wert", …) (SubjectAltNames)
        role (str): Die Rolle des beantragten Zertifikats (Role)
        not_before (DateTime): Gültigkeitsbeginn des Zertifikats (Zeitzone: UTC) (xsd:dateTime) (NotBefore)
        not_after (DateTime): Gültigkeitsende des Zertifikats (Zeitzone: UTC) (xsd:dateTime) (NotAfter)
        additional_name (str): Name des Antragsstellers (AdditionalName)
        additional_email (str): E-Mail-Adresse des Antragstellers (AdditionalEMail)
        additional_unit (str): Abteilung des Antragsstellers (AdditionalUnit)
    """
    ra_id: int
    subject: str
    subject_alt_names: List[str]
    role: str
    not_before: DateTime
    not_after: DateTime
    additional_name: str
    additional_email: str
    additional_unit: str


@dataclass
class DFNCERTTypesExtendedRequestParameters:
    """6.3.2 DFNCERTTypesExtendedRequestParameters

    Attributes:
        ra_id (int): RA Nummer des Antrags (RaID)
        subject (str): Subject DN des Antrags (Subject)
        subject_alt_names (List[str]): Subject Alternative Names als Array von Strings. Format ist: ("typ:wert", …) (SubjectAltNames)
        role: (str): Die Rolle des beantragten Zertifikats (Roile)
        not_before (DateTime): Gültigkeitsbeginn des Zertifikats (Zeitzone: UTC) (xsd:dateTime)
        not_after (DateTime): Gültigkeitsende des Zertifikats (Zeitzone: UTC) (xsd:dateTime)
        additional_name (str): Name des Antragsstellers (AdditionalName)
        additional_email (str): Kontakt-E-Mail-Adresse des Antragstellers (AdditionalEMail)
        additional_unit (str): Abteilung des Antragsstellers (AdditionalUnit)
        validity_days (int): Gültigkeitsdauer des Zertifikats in Tagen (ValidityDays)
        email_addresses (List[str]): Liste mit allen E-Mail-Adressen des gegebenen Antrags, die in das Zertifikat aufgenommen werden sollen (für Anträge, die nach dem 1.7.2014 gestellt wurden)
    """

    ra_id: int
    subject: str
    subject_alt_names: List[str]
    role: str
    not_before: DateTime
    not_after: DateTime
    additional_name: str
    additional_email: str
    additional_unit: str
    validity_days: int
    mail_addresses: List[str]


@dataclass
class EMail:
    """6.3.3 Email

    Attributes:
        local (str): Lokaler-Part der E-Mail-Adresse (Local)
        domain (str): Domain-Part der E-Mail-Adresse (Domain)
        state (str): Status des Eintrags (EMailState)
        request_serial (int): Antragsnummer des zugehörigen Zertifikatantrags
        location (str): Ort, an dem die E-Mail-Adresse im Zertifikat steht (EMailLocation)
        last_send_date (DateTime): Zeitpunkt, an dem die letzte Bestätigungs-E-Mail versendet wurde (Zeitzone: UTC) (xsd:dateTime)
        state_change_date (DateTime): Zeitpunkt, an dem der State verändert wurde. (Zeitzone: UTC) (xsd:dateTime)

    Values of EMailState:
        PENDING: Bestätigung für die E-Mail-Adresse steht noch aus
        REJECTED: E-Mail-Adresse wurde zurückgewiesen
        CONFIRMED: E-Mail-Adresse wurde durch den Nutzer bestätigt
        WHITELISTED: E-Mail-Adresse wurde durch die Whitelist bestätigt

    Values of EMailLocation:
        DN: E-Mail-Adresse befindet sich im DN
        SAN: E-Mail-Adresse befindet sich im Subject-AltName
        DN_AND_SAN: E-Mail-Adresse sowohl im DN als auch im Subject-AltName
    """
    local: str
    domain: str
    state: str
    request_serial: int
    location: str
    last_send_date: DateTime
    state_change_date: DateTime


@dataclass
class DFNCERTTypesRequestInfo:
    """6.3.4 DFNCERTTypesRequestInfo

    Attributes:
        serial (int): Seriennummer des Antrags (Serial)
        same_dn_serials (List[int]): Liste mit Seriennummern von Zertifikaten, die den gleichen Subject DN tragen (SameDNSerials)
        status (str): Status des Eintrags (NEW, PENDING, RENEW, APPROVED, DELETED, ARCHIVED) (Status)
        parameters (str) : Struktur mit allen veränderbaren Parametern eines Zertifikatantrags (DFNCERTRequestParameters) (Parameters)
        public_key (str): Der öffentliche Schlüssel des Antrags in OpenSSL-Ausgabeformat (PublicKey)
        public_key_algorithm (str): Der verwendete Algorithmus des Schlüssels (PublicKeyAlgorithm)
        public_key_digest (str): Ein SHA-1 über den öffentlichen Schlüssel (PublicKeyDigest)
        public_key_length (int): Die Länge des öffentlichen Schlüssels in Bit (PublicKeyLength)
        publish (bool): Flagge für die Veröffentlichung des Antrags (Publish)
        signature_algorithm (str): Der verwendete Algorithmus bei der Signatur des Antrags (SignatureAlgorithm)
        date_submitted (str): Datum an dem der Antrag einging (Zeitzone: UTC) (DateSubmitted)
        date_approved (str): Das Datum der Genehmigung des Antrags (Zeitzone: UTC) (DateApproved)
        date_deleted (str): Das Datum der Löschung des Antrags (Zeitzone: UTC) (DateDeleted)

    values of status:
        NEW: Ein Zertifikatantrag (Request) ist im Zustand NEW, wenn er initial neu erzeugt worden ist.
        RENEW: Ein Request, der von einem achivierten Request abgeleitet worden ist ("Kopie").
        PENDING: Ein neuer oder erneuerter Request, der von einem CAO1 verändert worden ist.
        DELETED: Ein gelöschter Request. Von diesem wurde kein Zertifikat erzeugt.
        APPROVED: Ein freigegebener Request. Aus diesem Request basierend soll nun ein Zertifikat erzeugt werden.
        ARCHIVED: Ein Request, von dem ein Zertifikat erzeugt worden ist.

    """
    serial: int
    same_dn_serials: List[int]
    status: str
    parameters: DFNCERTTypesRequestParameters
    public_key: str
    public_key_algorithm: str
    public_key_digest: str
    public_key_length: int
    publish: bool
    signature_algorithm: str
    date_submitted: str
    date_approved: str
    date_deleted: str


@dataclass
class DFNCERTTypesExtendedRequestInfo:
    """6.3.5 DFNCERTTypesExtendedRequestInfo

    Attributes:
        serial (int): Seriennummer des Antrags (Serial)
        same_dn_serials (List[int]): Liste mit Seriennummern von Zertifikaten, die den gleichen Subject DN tragen (SameDNSerials)
        status (str): Status des Eintrags (s. DFNCERTTypesRequestInfo) (Status)
        parameters (tns:DFNCERTExtendedRequestParameters): Struktur mit allen veränderbaren Parametern (Parameters)
        public_key (str): Der öffentliche Schlüssel des Antrags in OpenSSL-Ausgabeformat (PublicKey)
        public_key_algorithm (str): Der verwendete Algorithmus des Schlüssels (PublicKeyAlgorithm)
        public_key_digest (str): Ein SHA-1 über den öffentlichen Schlüssel (PublicKeyDigest)
        public_key_length (int): Die Länge des öffentlichen Schlüssels in Bit (PublicKeyLength)
        publish (bool): Flagge für die Veröffentlichung des Antrags (Publish)
        signature_algorithm (str): Der verwendete Algorithmus bei der Signatur des Antrags (SignatureAlgorithm)
        date_submitted (str): Datum an dem der Antrag einging (DateSubmitted)
        date_approved (str): Das Datum der Genehmigung des Antrags (DateApproved)
        date_deleted (str): Das Datum der Löschung des Antrags (DateDeleted)
        signer_certificate_serial (int): Seriennummer des Unterzeichner-Zertifikats (SignerCertificateSerial)
        signer_cn (str): Subject-CN des Unterzeichner-Zertifikats (SignerCN)

    """
    serial: int
    same_dn_serials: List[int]
    status: str
    parameters: str
    public_key: str
    public_key_algorithm: str
    public_key_digest: str
    public_key_length: str
    publish: bool
    signature_algorithm: str
    date_submitted: str
    date_approved: str
    date_deleted: str
    signer_certificate_serial: int
    signer_cn: str


@dataclass
class DFNCERTTypesRequestData:
    """6.3.6 DFNCERTTypesRequestData

    Attributes:
        serial (int): Seriennummer des Antrags (Serial)
        ra_id (int): Nummer der RA, 0 für die Master-RA (RaID)
        pkcs10 (str): Der Zertifikatantrag im PEM-Format (PKCS10)
        alt_names (List[str]): Subject Alternative Names in der Form ("typ:wert", …) (tns1:ArrayOfString) (AltNames)
        role (str): Die Rolle des beantragten Zertifikats (Role)
        add_name (str): Vollständiger Name des Antragstellers (AddName)
        add_email (str): E-Mail Adresse des Antragstellers (AddEMail)
        add_org_unit (str): Abteilung des Antragstellers (AddOrgUnit)
        publish (bool): Veröffentlichung des Zertifikats (Publish)
    """
    serial: int
    ra_id: int
    pksc10: str
    alt_names: List[str]
    role: str
    add_name: str
    add_email: str
    add_org_unit: str
    publish: bool


@dataclass
class DFNCERTTypesRenewRequestResult:
    """6.3.7 DFNCERTTypesRenewRequestResult

    Attributes:
        serial (int): Seriennummer des Antrags (Serial)
        server (bool): Flag, das angibt, ob es sich um einen Antrag für ein Server-Zertifikat handelt. (Server)
        publish (bool): Veröffentlichung des Zertifikats (Publish)
        has_changed (bool): Flag, das angibt, ob der Wert von Publish beim erneuerten Antrag geändert wurde. (HasChanged)
    """
    serial: int
    server: bool
    publish: bool
    has_changed: bool


@dataclass
class DFNCERTTypesRevocationParameters:
    """6.4.1 DFNCERTTypesRevocationParameters

    Attributes:
        reason (str): Grund der Sperrung
    """
    reason: str


@dataclass
class DFNCERTTypesRevocationInfo:
    """6.4.2 DFNCERTTypesRevocationInfo

    Attributes:
        status (str): Status des Eintrags (Status)
        serial (int): Seriennummer des Eintrags (Serial)
        certificate_serial (int): Seriennummer des zu sperrenden Zertifikats (CertificateSerial)
        ra_id (int): RA-Nummer des Eintrags (RaID)
        date_submitted (str): Datum an dem der Antrag einging (Zeitzone: UTC) (DateSubmitted)
        date_approved (str): Das Datum der Genehmigung des Antrags (Zeitzone: UTC) (DateApproved)
        date_deleted (str): Das Datum der Löschung des Antrags (Zeitzone: UTC) (DateDeleted)
        parameters (DFNCERTTypesRevocationParameters): Parameter für einen Sperrantrag (Grund der Sperrung) (Parameters)
    """
    status: int
    serial: int
    certificate_serial: int
    ra_id: int
    date_submitted: str
    date_approved: str
    date_deleted: str
    parameters: DFNCERTTypesRevocationParameters


@dataclass
class DFNCERTTypesDomain:
    """6.5.1 DFNCERTTypesDomain

    Attributes:
        name (str): Domain-Name (Name)
        type (str): Typ (server, server-host, email oder email-host) (Type)
        secret (bool): Versteckt vor der Öffentlichkeit (Secret)
        approved (bool): Freigegeben (Approved)
        approved_date (DateTime): Freigabezeitpunkt (Zeitzone: UTC) (xsd:dateTime) (ApprovedDate)
    """
    name: str
    type: str
    secret: bool
    approved: bool
    approved_date: DateTime


@dataclass
class DFNCERTTypesExtendedDomain:
    """6.5.2 DFNCERTTypesExtendedDomain

    Attributes:
        name (str): Domain-Name
        type (str): Typ (server, server-host, email oder email-host)
        secret (bool): Versteckt vor der Öffentlichkeit
        approved (bool): Freigegeben
        approved_date (str): Freigabezeitpunkt (Zeitzone: UTC) (xsd:dateTime)
        method (str): Prüfmethode, nach der die Domain validiert wurde/werden soll
        br_version (str): Versionsnummer der Baseline-Requirements, auf die sich die Prüfmethode bezieht
        challange_mail_address (str): E-Mail-Adresse, an die die Challenge-E-Mail versendet wird/wurde
        last_challange_mail_sent (DateTime): Datum, an dem die letzte Challenge-E-Mail versendet wurde (Zeitzone: UTC) (xsd:dateTime)
        valid_until (DateTime): Gültigkeitsende (Zeitzone: UTC) (xsd:dateTime)
    """
    name: str
    type: str
    secret: bool
    approved: bool
    approved_date: DateTime
    method: str
    br_version: str
    challange_mail_address: str
    last_challange_mail_sent: DateTime
    valid_until: DateTime


@dataclass
class DFNCERTTypesDomainACL:
    """6.5.3 DFNCERTTypesDomainACL

    Attributes:
        ra_id (int): RA_ID für die diese Liste gilt (RaID)
        allowed (List[str]): Liste erlaubter Aktionen (Whitelist) (Allowed)
    """
    ra_id: int
    allowed: List[str]


@dataclass
class DFNCERTTypesDomainListResult:
    """6.5.4 DFNCERTTypesDomainListResult

    Attributes:
        change (str): Aktuelle Änderungsprüfsumme (Change)
        result (List[DFNCERTTypesDomain]): Liste mit gefundenen Domain-Einträgen (Result)
        acl (DFNCERTTypesDomainACL): Zugriffsrechte für angeforderte RA_ID (ACL)
    """
    change: str
    result: List[DFNCERTTypesDomain]
    acl: DFNCERTTypesDomainACL


@dataclass
class DFNCERTTypesExtendedDomainListResult:
    """6.5.5 DFNCERTTypesExtendedDomainListResult

    Attributes:
        result (List[DFNCERTTypesExtendedDomain]): Liste mit gefundenen Domain-Einträgen (Result)
        acl (DFNCERTTypesDomainACL): Zugriffsrechte für angeforderte RA_ID (ACL)
    """
    result: List[DFNCERTTypesExtendedDomain]
    acl: DFNCERTTypesDomainACL


@dataclass
class DFNCERTTypesDeleteDomain2Result:
    """6.5.6 DFNCERTTypesDeleteDomain2Result

    Attributes:
        change (str): Aktuelle Änderungsprüfsumme (Change)
        cert_infos (List[DFNCERTTypesShortCertInfo]): Liste mit gefundenen Zertifikat-Einträgen (CertInfos)
    """
    change: str
    cert_infos: List[DFNCERTTypesShortCertInfo]


@dataclass
class DFNCERTTypesTLDs:
    """6.5.7 DFNCERTTypesTLDs

    Attributes:
        tdls (List[str]): Liste mit den Top-level-domains (TLDs)
    """
    tdls: List[str]


@dataclass
class DFNCERTTypesValidDomain:
    """6.5.8 DFNCERTTypesValidDomain

    Attributes:
        name (str): Domain-Name
        type (str): Typ (server, server-host, email oder email-host)
    """
    name: str
    type: str


@dataclass
class DFNCERTTypesValidationParameter:
    """6.5.9 DFNCERTTypesValidationParameter

    Attributes:
        name (str): Domain-Name (Name)
        method (str): Prüfmethode (2-Domain-Contact-Mail-SOA oder 4-Constructed-Mail) (Method)
        email (str): E-Mail-Adresse, die zur Prüfmethode passt. (EMail)
        adns (List[str]): Liste der zur Prüfmethode passenden Authorization Domain Names (ADNs)

    Bzgl. Prüfmethoden siehe setValidationParameter.
    """
    name: str
    method: str
    email: str
    adns: List[str]


@dataclass
class DFNCERTTypesSendChallengeEMailResult:
    """6.5.10 DFNCERTTypesSendChallengeEMailResult

    Attributes:
        change (str): Aktuelle Änderungsprüfsumme (Change)
        last_challende_email_sent (DateTime): Datum, an dem die Challenge-E-Mail gesendet wurde. (Zeitzone: UTC) (xsd:dateTime) (LastChallengeEMailSent)
    """
    change: str
    last_challende_email_sent: DateTime
