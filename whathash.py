#!/usr/bin/env python3

from os import system, name
from sys import exit

HASHLIST = {
    '4_chars': ['CRC-16', 'CRC-16-CCITT', 'FCS-16'],
    '8_chars': ['CRC-32', 'ADLER-32', 'CRC-32B', 'XOR-32', 'GHash-32-3', 'GHash-32-5'],
    '13_chars': ['DES(Unix)'],
    '16_chars': ['MD5(Half)', 'MD5(Middle)', 'MySQL'],
    '32_chars': ['Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))',
                 'Haval128', 'Haval128HMAC', 'MD2', 'MD2(HMAC)', 'MD4', 'MD4(HMAC)', 'MD5', 'MD5(HMAC)',
                 'MD5(HMAC(Wordpress))', 'NTLM', 'RAdminv2x', 'RipeMD-128', 'RipeMD-128(HMAC)', 'SNEFRU-128',
                 'SNEFRU-128(HMAC)', 'Tiger-128', 'Tiger-128(HMAC)', 'md5($pass.$salt)', 'md5($salt.\'-\'.md5($pass))',
                 'md5($salt.$pass)', 'md5($salt.$pass.$salt)', 'md5($salt.$pass.$username)', 'md5($salt.md5($pass))',
                 'md5($salt.md5($pass).$salt)', 'md5($salt.md5($pass.$salt))', 'md5($salt.md5($salt.$pass))',
                 'md5($salt.md5(md5($pass).$salt))', 'md5($username.0.$pass)', 'md5($username.LF.$pass)',
                 'md5($username.md5($pass).$salt)', 'md5(md5($pass))', 'md5(md5($pass).$salt)',
                 'md5(md5($pass).md5($salt))',
                 'md5(md5($salt).$pass)', 'md5(md5($salt).md5($pass))', 'md5(md5($username.$pass).$salt)',
                 'md5(md5(md5($pass)))', 'md5(md5(md5(md5($pass))))', 'md5(md5(md5(md5(md5($pass)))))',
                 'md5(sha1($pass))',
                 'md5(sha1(md5($pass)))', 'md5(sha1(md5(sha1($pass))))', 'md5(strtoupper(md5($pass)))'],
    '40_chars': ['Haval-160', 'Haval-160(HMAC)', 'MySQL5', 'RipeMD-160', 'RipeMD-160(HMAC)', 'SHA-1', 'SHA-1(HMAC)',
                 'SHA-1(MaNGOS)', 'SHA-1(MaNGOS2)', 'Tiger-160', 'Tiger-160(HMAC)', 'sha1($pass.$salt)',
                 'sha1($salt.$pass)',
                 'sha1($salt.md5($pass))', 'sha1($salt.md5($pass).$salt)', 'sha1($salt.sha1($pass))',
                 'sha1($salt.sha1($salt.sha1($pass)))',
                 'sha1($username.$pass)', 'sha1($username.$pass.$salt)', 'sha1(md5($pass))', 'sha1(md5($pass).$salt)',
                 'sha1(md5(sha1($pass)))',
                 'sha1(sha1($pass))', 'sha1(sha1($pass).$salt)', 'sha1(sha1($pass).substr($pass,0,3))',
                 'sha1(sha1($salt.$pass))',
                 'sha1(sha1(sha1($pass)))', 'sha1(strtolower($username).$pass)'],
    '48_chars': ['Haval-192', 'Haval-192(HMAC)', 'Tiger-192', 'Tiger-192(HMAC)'],
    '56_chars': ['Haval-224', 'Haval-224(HMAC)', 'SHA-224', 'SHA-224(HMAC)'],
    '64_chars': ['SHA-256', 'SHA-256(HMAC)', 'Haval-256', 'Haval-256(HMAC)', 'GOST R 34.11-94', 'RipeMD-256',
                 'RipeMD-256(HMAC)',
                 'SNEFRU-256', 'SNEFRU-256(HMAC)', 'SHA-256(md5($pass))', 'SHA-256(sha1($pass))'],
    '80_chars': ['RipeMD-320', 'RipeMD-320(HMAC)'],
    '96_chars': ['SHA-384', 'SHA-384(HMAC)'],
    '128_chars': ['SHA-512', 'SHA-512(HMAC)', 'Whirlpool', 'Whirlpool(HMAC)'],
    'prefixes': {
        '0x': ['Lineage II C4'],
        '$BLAKE2$': ['BLAKE'],
        '$DCC2$': ['Domain Cached Credentials 2'],
        '$H$': ['MD5(phpBB3)'],
        '$2a$': ['OpenBSD Blowfish'],
        '$2y$': ['Blowfish', 'Crypt(3)'],
        '$1$': ['MD5(Unix)', 'MD5-CRYPT', 'Cisco-IOS'],
        '$2$': ['bcrypt $2*$'],
        '$3$': ['WinNT MD4'],
        '$5$': ['SHA-256(Unix)'],
        '$6$': ['SHA-512(Unix)'],
        '$8$': ['Cisco-IOS $8$ (PBKDF2-SHA256)'],
        '$9$': ['Cisco-IOS $9$ (SCRYPT)'],
        '$P$': ['MD5(Wordpress)'],
        '$P$B': ['MD5(Wordpress)'],
        '$S$5': ['Drupal v8'],
        '$P$9': ['MD5(Wordpress)', 'PHPASS', 'MD5(Joomla)'],
        '$oldoffice$': ['MS Office 2003'],
        '$office$*2007*': ['MS Office 2007'],
        '$office$*2010*': ['MS Office 2010'],
        '$office$*2013*': ['MS Office 2013'],
        '$pdf$1*2*40*-1*0*16': ['PDF 1.1-1.3'],
        '$pdf$2*3*128*-1028*1*16': ['PDF 1.4-1.6'],
        '$pdf$5*5*256*-1028*1*16': ['PDF 1.7 Level 3'],
        '$pdf$5*6*256*-1028*1*16': ['PDF 1.7 Level 8'],
        'SCRYPT': ['SCRYPT'],
        '$cram_md5$': ['CRAM-MD5'],
        '$apr': ['MD5(APR)'],
        '$racf$': ['RACF'],
        '$krb5pa$': ['Kerberos 5'],
        '*': ['MySQL-160bit'],
        'sha1$': ['SHA-1(Django)'],
        'sha256': ['SHA-256(Django)'],
        'sha384': ['SHA-384(Django)'],
        '{smd5}': ['AIX(SMD5)'],
        '{ssha1}': ['AIX(SSHA-1)'],
        '{ssha256}': ['AIX(SSHA-256)'],
        '{ssha512}': ['AIX(SSHA-512)'],
    },
    'specials': {
        ':': ['md5($pass.$salt) - Joomla', 'SAM'],
    }
}


def banner():
    banner = '''   
              __          __   __                __    
    .--.--.--|  |--.---.-|  |_|  |--.---.-.-----|  |--.   [Author]:fu11p0w3r
    |  |  |  |     |  _  |   _|     |  _  |__ --|     |   [Version]: 0.1
    |________|__|__|___._|____|__|__|___._|_____|__|__|   [Info]: tool for detect hash algorithms
                                                        '''
    system('cls') if name == 'nt' else system('clear')
    print(banner)


def get_algorithm(hash):
    global HASHLIST
    h_size = len(hash)
    for prefix in HASHLIST['prefixes']:
        if prefix in hash[0:23]:
            return HASHLIST['prefixes'][prefix]
    if ':' in hash[32:33]:
        return HASHLIST['specials'][':']
    elif h_size >= 4 and h_size <= 128 and hash.isalnum() == True:
        return HASHLIST[f'{h_size}_chars']
    else:
        return 'Not Detected'


if __name__ == '__main__':
    banner()
    try:
        hash = str(input('[~]Hash => '))
    except KeyboardInterrupt:
        print('\n[*]Byeee :)')
        exit(0)
    except:
        print('[X]Error, pls try again with correct value!')
        exit(0)
    else:
        result = get_algorithm(hash)
        print('===============================================')
        if result != 'Not Detected':
            result.sort()
            print(f'Entered hash is {hash}')
            print("\nPossible algorithms:")
            for _ in result:
                print(f'[+]{_}')
        else:
            print('[X]Not detected. Try other hash if you have')
