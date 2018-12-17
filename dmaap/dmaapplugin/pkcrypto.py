"""
RSA encryption and decryption functions

pkcrypto.py

Written by:    Terry Schmalzried
Date written:  September 20, 2017
Last updated:  September 27, 2017
"""

from __future__ import print_function
import sys, subprocess, json


def encrypt_string(clear_text):
    """RSA encrypt a string of limited length"""

    # Use Carsten's jar files and the key already installed on the host
    cmd = ['/usr/bin/java',
           '-cp', '/opt/lib/log4j-1.2.17.jar:/opt/lib/ncomp-utils-java-1.17070100.0-SNAPSHOT.jar',
           'org.openecomp.ncomp.utils.CryptoUtils',
           'public-key-encrypt',
           '/opt/dcae/server.public'
          ]
    try:
        p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout_data, stderr_data) = p.communicate(input=clear_text)
    except Exception as e:
        print("encrypt_string exception: {}".format(e), file=sys.stderr)
        return None

    if stderr_data:
        print("encrypt_string stderr: {}".format(stderr_data), file=sys.stderr)
        return None

    return stdout_data.replace(" ","").rstrip('\n')


def decrypt_string(encrypted_text):
    """RSA decrypt a string"""

    # Use Carsten's jar files and the key already installed on the host
    cmd = ['sudo', '/usr/bin/java',
           '-cp', '/opt/lib/log4j-1.2.17.jar:/opt/lib/ncomp-utils-java-1.17070100.0-SNAPSHOT.jar',
           'org.openecomp.ncomp.utils.CryptoUtils',
           'public-key-decrypt',
           '/opt/dcae/server.private',
           encrypted_text
          ]
    try:
        p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout_data, stderr_data) = p.communicate()
    except Exception as e:
        print("decrypt_string exception: {}".format(e), file=sys.stderr)
        return None

    if stderr_data:
        print("decrypt_string stderr: {}".format(stderr_data), file=sys.stderr)
        return None

    return stdout_data.rstrip('\n')


def decrypt_obj(obj):
    """decrypt all RSA string values in a python nested object and embedded JSON string objects"""

    if isinstance(obj, dict):
        return {k: decrypt_obj(v) for k,v in obj.items()}
    elif isinstance(obj, list):
        return [decrypt_obj(v) for v in obj]
    elif isinstance(obj, basestring):
        if obj.startswith("rsa:"):
            obj2 = decrypt_string(obj)
            if obj2 is not None:
                return obj2
        else:
            try:
                obj2 = json.loads(obj)
                return json.dumps(decrypt_obj(obj2))
            except Exception as e:
                pass
    return obj


if __name__ == '__main__':
    clear_text = "a secret"
    print("Encrypting:  {}".format(clear_text))
    encrypted = encrypt_string(clear_text)
    print("Encrypted:   {}".format(encrypted))
    print("Decrypted:   {}".format(decrypt_string(encrypted)))


    # print("\nWhitespace in the encrypted string does not seem to matter:")
    # encrypted = 'rsa:Y2feMIiKwR0Df3zVDDf1K+4Lkt9vxGnT8UugHkjNLiht67PwXRJFP6/BbmZO9NhlOAMV3MLWwbhU  GikE96K7wuQaQVYOmAYNNuVDWLdvbW80pZVGKYgQsmrLizOhPbhD+adG7bdIiNMNMBOKk+XQMTLa  d77KzAQmZO2wLj0Z3As='
    # print("Decrypted:   {}".format(decrypt_string(encrypted)))

    # encrypted = '''rsa:Y2feMIiKwR0Df3zVDDf1K+4Lkt9vxGnT8UugHkjNLiht67PwXRJFP6/BbmZO9NhlOAMV3MLWwbhU
    #                     GikE96K7wuQaQVYOmAYNNuVDWLdvbW80pZVGKYgQsmrLizOhPbhD+adG7bdIiNMNMBOKk+XQMTLa
    #                     d77KzAQmZO2wLj0Z3As='''
    # print("Decrypted:   {}".format(decrypt_string(encrypted)))


    print("\nDecrypt some dicts:")
    print("Decrypted:  {}".format(decrypt_obj('not encrypted')))
    print("Decrypted:  {}".format(decrypt_obj(encrypted)))
    print("Decrypted:  {}".format(decrypt_obj({
        "key1":encrypted,
        "key2":"not encrypted",
        "key3":encrypted,
        "key4":{
            "key11":encrypted,
            "key12":"not encrypted",
            "key13":encrypted,
            "key14":[
                encrypted,
                "not encrypted",
                encrypted
            ]
        }
    })))


    print("\nDecrypt some JSON:")
    encrypted = json.dumps([{ "username": "m01234@bogus.att.com",
                              "password": encrypt_string("N0t_a-Rea1/passw0rd"),
                              "registry": "dockercentral.it.att.com:12345"
                          }])
    print("Encrypted:   {}".format(encrypted))
    print("Decrypted:   {}".format(decrypt_obj(encrypted)))


    print("\nDecrypt a dict that contains a json string containing encrypted keys:")
    a_dict = {
        "clear_txt": clear_text,
        "encrypted_str": encrypt_string(clear_text),
        "json_str": encrypted
    }
    print("Decrypted:   {}".format(decrypt_obj(a_dict)))


    print("\nDecrypt a json string that contains a dict that contains a json string containing encrypted keys:")
    print("Decrypted:   {}".format(decrypt_obj(json.dumps(a_dict))))
