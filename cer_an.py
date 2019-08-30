import OpenSSL
import time
from dateutil import parser
from gmssl.func import list_to_bytes


def cer_analysis(ceradd):
    
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(ceradd).read())
    print(type(open(ceradd).read()))
    print(open(ceradd).read())
    print(type(cert))
    print(cert)
    certIssue = cert.get_issuer()
    version = cert.get_version()+1
    sernum = hex(cert.get_serial_number())
    signature = cert.get_signature_algorithm().decode("UTF-8")
    comname = certIssue.commonName
    datetime_struct = parser.parse(cert.get_notBefore().decode("UTF-8"))
    starttime = datetime_struct.strftime('%Y-%m-%d %H:%M:%S')
    datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))
    endtime = datetime_struct.strftime('%Y-%m-%d %H:%M:%S')
    flag = cert.has_expired()
    long = cert.get_pubkey().bits()
    public = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8")
    ext = cert.get_extension_count()
    components = certIssue.get_components()
    l = ['证书版本：', version, ' 证书序列号：',sernum, "证书中使用的签名算法: ",signature, "颁发者:",comname, "有效期从:",starttime, "到", endtime, "证书是否已经过期:",flag, "公钥长度" ,long, "公钥:",public, "主体信息",components, ext]
    return l


    


if __name__=='__main__':
    ceradd = 'cacertGM.cer'
    l = cer_analysis(ceradd)
    print(l)
