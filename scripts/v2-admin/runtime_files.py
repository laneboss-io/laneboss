"""Successful file paths from the Claude 2.1.296 runtime measurement.

Only these names are considered. Missing optional data files stay absent; no directory is
enumerated or mounted. The CA bundle alone supplies trust; individual certificate
names remain in the inventory only to record their omission. Certificate labels
use spaces here and underscores in installed filenames.
"""

import os


CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
CA_ALIAS = "/etc/ssl/cert.pem"

# Successful execve targets in the retained Claude 2.1.296 startup audit.
START_PROGRAMS = ("/usr/bin/git", "/usr/bin/sh", "/usr/bin/uname")

ETC_FILES = (
    "/etc/gai.conf",
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/machine-id",
    "/etc/nsswitch.conf",
    "/etc/os-release",
    CA_ALIAS,
)

CERT_LABELS = """
002c0b4f.0
0179095f.0
062cdee6.0
064e0aa9.0
06dc52d5.0
09789157.0
0a775a30.0
0b1b94ef.0
0b9bc432.0
0bf05006.0
0f5dc4f3.0
0f6fa695.0
1001acf7.0
14bc7599.0
1cef98f5.0
1d3472b9.0
1e08bfd1.0
1e09d511.0
2923b3f9.0
2ae6433e.0
2ccbdda3.0
30e1580d.0
32888f65.0
3bde41ac.0
3e359ba6.0
3fb36b73.0
40193066.0
4042bcee.0
406c9bb1.0
48bec511.0
4b718d9b.0
4bfab552.0
5443e9e3.0
54657681.0
5860aaa6.0
5931b5bc.0
5f15c80c.0
5f618aec.0
607986c7.0
616816f6.0
6805c744.0
68dd7389.0
6a9bdba3.0
6b99d060.0
6d41d539.0
6fa5da56.0
749e9e03.0
75d1b2ed.0
7719f463.0
773e07ad.0
7a3adc42.0
7a780d93.0
7f3d5d1d.0
7fa05551.0
8160b96c.0
8508e720.0
865fbdf9.0
878d9bca.0
8cb5ee0f.0
8d89cda1.0
8f103249.0
9046744a.0
90c5a3c8.0
930ac5d2.0
9482e63a.0
9846683b.0
988a38cb.0
9b46e03d.0
9bf03295.0
9d04f354.0
9e654b62.0
9ef4a08a.0
9f727ac7.0
ACCVRAIZ1.pem
AC RAIZ FNMT-RCM.pem
AC RAIZ FNMT-RCM SERVIDORES SEGUROS.pem
ANF Secure Server Root CA.pem
Amazon Root CA 1.pem
Amazon Root CA 4.pem
Atos TrustedRoot 2011.pem
Atos TrustedRoot Root CA ECC TLS 2021.pem
Buypass Class 3 Root CA.pem
COMODO ECC Certification Authority.pem
COMODO RSA Certification Authority.pem
Certigna Root CA.pem
Certum Trusted Root CA.pem
D-TRUST BR Root CA 2 2023.pem
D-TRUST EV Root CA 2 2023.pem
D-TRUST Root Class 3 CA 2 2009.pem
D-TRUST Root Class 3 CA 2 EV 2009.pem
DigiCert Global Root G3.pem
DigiCert TLS RSA4096 Root G5.pem
GTS Root R4.pem
GlobalSign ECC Root CA - R4.pem
GlobalSign Root CA - R6.pem
GlobalSign Root E46.pem
Go Daddy Root Certificate Authority - G2.pem
HARICA TLS ECC Root CA 2021.pem
IdenTrust Commercial Root CA 1.pem
Izenpe.com.pem
Microsoft RSA Root Certificate Authority 2017.pem
OISTE WISeKey Global Root GB CA.pem
QuoVadis Root CA 3 G3.pem
SSL.com EV Root Certification Authority ECC.pem
SSL.com TLS RSA Root CA 2022.pem
SZAFIR ROOT CA2.pem
Sectigo Public Server Authentication Root E46.pem
Security Communication RootCA2.pem
TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1.pem
TWCA CYBER Root CA.pem
TWCA Root Certification Authority.pem
Telekom Security TLS ECC Root 2020.pem
TrustAsia TLS RSA Root CA.pem
TunTrust Root CA.pem
UCA Global G2 Root.pem
USERTrust ECC Certification Authority.pem
USERTrust RSA Certification Authority.pem
ca-certificates.crt
ca6e4ad9.0
e-Szigno Root CA 2017.pem
e-Szigno TLS Root CA 2023.pem
ed858448.0
""".strip().splitlines()

LIBRARIES = (
    "libc.so.6", "libdl.so.2", "libm.so.6", "libpcre2-8.so.0",
    "libpthread.so.0", "librt.so.1", "libz.so.1",
)

LOCALE_FILES = (
    "LC_ADDRESS",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES/SYS_LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
)


def paths():
    triplet = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}.get(os.uname().machine)
    if triplet is None:
        raise ValueError("measured runtime architecture is unsupported")
    result = list(ETC_FILES)
    result.extend("/etc/ssl/certs/" + name.replace(" ", "_") for name in CERT_LABELS)
    result.extend("/lib/" + triplet + "/" + name for name in LIBRARIES)
    result.extend("/usr/lib/locale/C.utf8/" + name for name in LOCALE_FILES)
    result.extend(("/usr/lib/locale/locale-archive", "/usr/share/locale/locale.alias",
                   "/usr/lib/" + triplet + "/gconv/gconv-modules.cache"))
    return sorted(set(result))
