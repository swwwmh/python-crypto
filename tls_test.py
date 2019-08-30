# -*- coding: utf-8 -*-
"""
Created on Mon Apr  8 09:13:15 2019

@author: mh
"""

from threading import Thread
from scapy.all import *
import requests
import ssl
import socket
load_layer("tls")

flag = 0

#num = int(input('抓包数量：'))
def version_test(msg_str):
    if 'version=TLS 1.0' in msg_str:
        version = 'TLS 1.0'
    elif 'version=TLS 1.1' in msg_str:
        version = 'TLS 1.1'
    elif 'version=TLS 1.2' in msg_str:
        version = 'TLS 1.2'
    elif 'version=TLS 1.3' in msg_str:
        version = 'TLS 1.3'
    else:
        version = 'error'
    return version
        
        
def cipher_test(msg_str):
    t = 0
    l = ['cipher=TLS_NULL_WITH_NULL_NULL', 'cipher=TLS_RSA_WITH_NULL_MD5', 'cipher=TLS_RSA_WITH_NULL_SHA', 'cipher=TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'cipher=TLS_RSA_WITH_RC4_128_MD5', 'cipher=TLS_RSA_WITH_RC4_128_SHA', 'cipher=TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'cipher=TLS_RSA_WITH_IDEA_CBC_SHA', 'cipher=TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'cipher=TLS_RSA_WITH_DES_CBC_SHA', 'cipher=TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_DES_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_DES_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_DES_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_DES_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_DH_anon_EXPORT_WITH_RC4_40_MD5', 'cipher=TLS_DH_anon_WITH_RC4_128_MD5', 'cipher=TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'cipher=TLS_DH_anon_WITH_DES_CBC_SHA', 'cipher=TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', 'cipher=Reserved to avoid conflicts with SSLv3', 'cipher=TLS_KRB5_WITH_DES_CBC_SHA', 'cipher=TLS_KRB5_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_KRB5_WITH_RC4_128_SHA', 'cipher=TLS_KRB5_WITH_IDEA_CBC_SHA', 'cipher=TLS_KRB5_WITH_DES_CBC_MD5', 'cipher=TLS_KRB5_WITH_3DES_EDE_CBC_MD5', 'cipher=TLS_KRB5_WITH_RC4_128_MD5', 'cipher=TLS_KRB5_WITH_IDEA_CBC_MD5', 'cipher=TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', 'cipher=TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', 'cipher=TLS_KRB5_EXPORT_WITH_RC4_40_SHA', 'cipher=TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', 'cipher=TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', 'cipher=TLS_KRB5_EXPORT_WITH_RC4_40_MD5', 'cipher=TLS_PSK_WITH_NULL_SHA', 'cipher=TLS_DHE_PSK_WITH_NULL_SHA', 'cipher=TLS_RSA_PSK_WITH_NULL_SHA', 'cipher=TLS_RSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_AES_128_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_DH_anon_WITH_AES_128_CBC_SHA', 'cipher=TLS_RSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_AES_256_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_AES_256_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_DH_anon_WITH_AES_256_CBC_SHA', 'cipher=TLS_RSA_WITH_NULL_SHA256', 'cipher=TLS_RSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_RSA_WITH_AES_256_CBC_SHA256', 'cipher=TLS_DH_DSS_WITH_AES_128_CBC_SHA256', 'cipher=TLS_DH_RSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 'cipher=TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'cipher=TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'cipher=Reserved to avoid conflicts with deployed implementations', 'cipher=Reserved to avoid conflicts', 'cipher=Reserved to avoid conflicts with deployed implementations', 'cipher=Unassigned', 'cipher=Reserved to avoid conflicts with widely deployed implementations', 'cipher=TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_DH_DSS_WITH_AES_256_CBC_SHA256', 'cipher=TLS_DH_RSA_WITH_AES_256_CBC_SHA256', 'cipher=TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', 'cipher=TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'cipher=TLS_DH_anon_WITH_AES_128_CBC_SHA256', 'cipher=TLS_DH_anon_WITH_AES_256_CBC_SHA256', 'cipher=Unassigned', 'cipher=TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'cipher=TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'cipher=TLS_PSK_WITH_RC4_128_SHA', 'cipher=TLS_PSK_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_PSK_WITH_AES_128_CBC_SHA', 'cipher=TLS_PSK_WITH_AES_256_CBC_SHA', 'cipher=TLS_DHE_PSK_WITH_RC4_128_SHA', 'cipher=TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_DHE_PSK_WITH_AES_128_CBC_SHA', 'cipher=TLS_DHE_PSK_WITH_AES_256_CBC_SHA', 'cipher=TLS_RSA_PSK_WITH_RC4_128_SHA', 'cipher=TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_RSA_PSK_WITH_AES_128_CBC_SHA', 'cipher=TLS_RSA_PSK_WITH_AES_256_CBC_SHA', 'cipher=TLS_RSA_WITH_SEED_CBC_SHA', 'cipher=TLS_DH_DSS_WITH_SEED_CBC_SHA', 'cipher=TLS_DH_RSA_WITH_SEED_CBC_SHA', 'cipher=TLS_DHE_DSS_WITH_SEED_CBC_SHA', 'cipher=TLS_DHE_RSA_WITH_SEED_CBC_SHA', 'cipher=TLS_DH_anon_WITH_SEED_CBC_SHA', 'cipher=TLS_RSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_RSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_DH_RSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_DH_RSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 'cipher=TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', 'cipher=TLS_DH_DSS_WITH_AES_128_GCM_SHA256', 'cipher=TLS_DH_DSS_WITH_AES_256_GCM_SHA384', 'cipher=TLS_DH_anon_WITH_AES_128_GCM_SHA256', 'cipher=TLS_DH_anon_WITH_AES_256_GCM_SHA384', 'cipher=TLS_PSK_WITH_AES_128_GCM_SHA256', 'cipher=TLS_PSK_WITH_AES_256_GCM_SHA384', 'cipher=TLS_DHE_PSK_WITH_AES_128_GCM_SHA256', 'cipher=TLS_DHE_PSK_WITH_AES_256_GCM_SHA384', 'cipher=TLS_RSA_PSK_WITH_AES_128_GCM_SHA256', 'cipher=TLS_RSA_PSK_WITH_AES_256_GCM_SHA384', 'cipher=TLS_PSK_WITH_AES_128_CBC_SHA256', 'cipher=TLS_PSK_WITH_AES_256_CBC_SHA384', 'cipher=TLS_PSK_WITH_NULL_SHA256', 'cipher=TLS_PSK_WITH_NULL_SHA384', 'cipher=TLS_DHE_PSK_WITH_AES_128_CBC_SHA256', 'cipher=TLS_DHE_PSK_WITH_AES_256_CBC_SHA384', 'cipher=TLS_DHE_PSK_WITH_NULL_SHA256', 'cipher=TLS_DHE_PSK_WITH_NULL_SHA384', 'cipher=TLS_RSA_PSK_WITH_AES_128_CBC_SHA256', 'cipher=TLS_RSA_PSK_WITH_AES_256_CBC_SHA384', 'cipher=TLS_RSA_PSK_WITH_NULL_SHA256', 'cipher=TLS_RSA_PSK_WITH_NULL_SHA384', 'cipher=TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'cipher=TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256', 'cipher=TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'cipher=TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256', 'cipher=TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'cipher=TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256', 'cipher=Unassigned', 'cipher=TLS_EMPTY_RENEGOTIATION_INFO_SCSV', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=TLS_AES_128_GCM_SHA256', 'cipher=TLS_AES_256_GCM_SHA384', 'cipher=TLS_CHACHA20_POLY1305_SHA256', 'cipher=TLS_AES_128_CCM_SHA256', 'cipher=TLS_AES_128_CCM_8_SHA256', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=TLS_FALLBACK_SCSV', 'cipher=Unassigned', 'cipher=TLS_ECDH_ECDSA_WITH_NULL_SHA', 'cipher=TLS_ECDH_ECDSA_WITH_RC4_128_SHA', 'cipher=TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_ECDHE_ECDSA_WITH_NULL_SHA', 'cipher=TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'cipher=TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_ECDH_RSA_WITH_NULL_SHA', 'cipher=TLS_ECDH_RSA_WITH_RC4_128_SHA', 'cipher=TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_ECDHE_RSA_WITH_NULL_SHA', 'cipher=TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'cipher=TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_ECDH_anon_WITH_NULL_SHA', 'cipher=TLS_ECDH_anon_WITH_RC4_128_SHA', 'cipher=TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_ECDH_anon_WITH_AES_128_CBC_SHA', 'cipher=TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'cipher=TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_SRP_SHA_WITH_AES_128_CBC_SHA', 'cipher=TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA', 'cipher=TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', 'cipher=TLS_SRP_SHA_WITH_AES_256_CBC_SHA', 'cipher=TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA', 'cipher=TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'cipher=TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', 'cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'cipher=TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', 'cipher=TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', 'cipher=TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', 'cipher=TLS_ECDHE_PSK_WITH_RC4_128_SHA', 'cipher=TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', 'cipher=TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA', 'cipher=TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA', 'cipher=TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256', 'cipher=TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384', 'cipher=TLS_ECDHE_PSK_WITH_NULL_SHA', 'cipher=TLS_ECDHE_PSK_WITH_NULL_SHA256', 'cipher=TLS_ECDHE_PSK_WITH_NULL_SHA384', 'cipher=TLS_RSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_RSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_DH_anon_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_DH_anon_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_RSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_RSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_DH_anon_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_DH_anon_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_PSK_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_PSK_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_PSK_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_PSK_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256', 'cipher=TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384', 'cipher=TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256', 'cipher=TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384', 'cipher=TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'cipher=TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'cipher=TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'cipher=TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'cipher=TLS_RSA_WITH_AES_128_CCM', 'cipher=TLS_RSA_WITH_AES_256_CCM', 'cipher=TLS_DHE_RSA_WITH_AES_128_CCM', 'cipher=TLS_DHE_RSA_WITH_AES_256_CCM', 'cipher=TLS_RSA_WITH_AES_128_CCM_8', 'cipher=TLS_RSA_WITH_AES_256_CCM_8', 'cipher=TLS_DHE_RSA_WITH_AES_128_CCM_8', 'cipher=TLS_DHE_RSA_WITH_AES_256_CCM_8', 'cipher=TLS_PSK_WITH_AES_128_CCM', 'cipher=TLS_PSK_WITH_AES_256_CCM', 'cipher=TLS_DHE_PSK_WITH_AES_128_CCM', 'cipher=TLS_DHE_PSK_WITH_AES_256_CCM', 'cipher=TLS_PSK_WITH_AES_128_CCM_8', 'cipher=TLS_PSK_WITH_AES_256_CCM_8', 'cipher=TLS_PSK_DHE_WITH_AES_128_CCM_8', 'cipher=TLS_PSK_DHE_WITH_AES_256_CCM_8', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_128_CCM', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_256_CCM', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8', 'cipher=TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8', 'cipher=TLS_ECCPWD_WITH_AES_128_GCM_SHA256', 'cipher=TLS_ECCPWD_WITH_AES_256_GCM_SHA384', 'cipher=TLS_ECCPWD_WITH_AES_128_CCM_SHA256', 'cipher=TLS_ECCPWD_WITH_AES_256_CCM_SHA384', 'cipher=TLS_SHA256_SHA256', 'cipher=TLS_SHA384_SHA384', 'cipher=Unassigned', 'cipher=TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC', 'cipher=TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC', 'cipher=TLS_GOSTR341112_256_WITH_28147_CNT_IMIT', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'cipher=TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'cipher=TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'cipher=TLS_PSK_WITH_CHACHA20_POLY1305_SHA256', 'cipher=TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256', 'cipher=TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256', 'cipher=TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256', 'cipher=TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384', 'cipher=TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256', 'cipher=Unassigned', 'cipher=TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=Unassigned', 'cipher=Reserved to avoid conflicts with widely deployed implementations', 'cipher=Reserved for Private Use']
    for i in range(len(l)):
        if l[i] in msg_str:
            cipher = l[i]
            break
        elif t>len(l):
            cipher = 'error'
        else:
            t = t+1
    return cipher
        
                
def packet_test(msg_str):
    if 'msgtype=client_hello' in msg_str:
        flag = 0
    elif 'msgtype=server_hello' in msg_str:
        flag = 1
    else:
        flag = 2
    return flag 
        
        
        
#def sniff_packet(num):
    #packets = sniff( lfilter=lambda x: TLS in x, count = num)
    #return packets
#print(packets.show())
#for i in range(0,num):
    #print(packets[i].display())
    #print(hexdump(packets[i]))
def get_url_ip(url):
    #url = input('目标url：')
    ip = socket.gethostbyname(url)
    print('url_ip:',ip)
    return ip



def request_url(url):
    global flag
    params = {'id': 'id', 'token': 'token'}
    urls = 'https://'+ url
    #i = 0
    while(flag != 1):
        #i=i+1
        requests.post(urls , data=params)
        #print('i=',i)



def main_scapy(url):
    global flag
    #url = input('目标url：')
    ip = get_url_ip(url)   
    ip1 = 'src or dst '+ip
    num = 40
    #print(1)
    packets = sniff(filter = ip1, lfilter=lambda x: TLS in x , count = num)
    #packets.show()
    #print(2)
    for i in range(len(packets)):
        msg_str = str(packets[i].payload[TLS].msg)
        #print(msg_str)
        flag = packet_test(msg_str)
        if flag == 0:
            li = [packets[i].payload[IP].src, packets[i].payload[IP].dst]
            version = version_test(msg_str)
            li.append(version)
            break
        else:
            pass
    #print('client:',src_ip)
    #print('server:',dst_ip)
    #packets.show()
    for n in range(len(packets)):
        msg_str = str(packets[n].payload[TLS].msg)
        flag = packet_test(msg_str)
        if flag == 1 and packets[n].payload[IP].src == li[1] and packets[n].payload[IP].dst == li[0]:
            cipher = cipher_test(msg_str)
            li.append(cipher)
            break
        else:
            pass
    #print('version:',version)
    #print('cipher:',cipher)
    if len(li) ==4:
        flag = 1
        print(li)
    else:
        main_scapy()
    
def main():
    url = input('目标url：')
    s1 = threading.Thread(target=request_url, args=(url, ))
    s2 = threading.Thread(target=main_scapy, args=(url, ))
    s1.start()
    s2.start()
    s1.join()
    s2.join()
    #print("exit")

if __name__ == '__main__':
	main()
    
    
    #print(main_scapy())
    #num = int(input('抓包数量：'))
    #packets = sniff( lfilter=lambda x: TLS in x, count = num)
    #msg_str = str(packets[0].payload[TLS].msg)
    #flag = packet_test(msg_str)
    #print(msg_str)
    #print(flag)
    
            
        
    

            
            
        
    
    
    
#tls_s = str(packets[0].payload[TLS].msg)

    
#src = source      源
#dst = destination 目的
