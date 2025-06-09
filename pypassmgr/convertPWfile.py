import os, argparse
from .pw_manager import _aes256cbc, ManagerClass
from getpass import getpass

def parseArgs():
    descriptString = \
        "Convert a ~/.pypassmgr/.backup file to a pypassmgr db file."
    parser = argparse.ArgumentParser(description=descriptString)
    fixedDir = os.path.expanduser("~") + "/.pypassmgr/"
    parser.add_argument('backup_file', nargs='?', type=str, 
        default=fixedDir+'.backup', help="path and file to load")
    args = parser.parse_args()
    return args

def main():
    args = parseArgs()
    Manager = ManagerClass()
    if not Manager.file_exist:
        Manager.createKeys()
    assert not Manager.pws, "pypassman db file already exists.  " + \
        "Please delete ~/.pypassmgr/.passwords_db and try again."
    oldPWfile = args.backup_file
    with open(oldPWfile, 'rb') as ff:
        file_bytes = ff.read()
    if file_bytes[:8] == b'Salted__':
        flag_enc = True
    else:
        flag_enc = False
    aesObj = _aes256cbc()
    if flag_enc:
        print("Encrypted file found...")
        _passw = getpass().encode()
        file_dec = aesObj.decrypt_from_backup(file_bytes, _passw).decode()
        aesObj.reset()
    else:
        print("Unencrypted file found...")
        file_dec = file_bytes.decode()
    fileList = file_dec.split('\n')
    numEntries = fileList.count('#################')
    print('...containing {:d} entries'.format(numEntries))
    pwArray = []
    tempLabel = []
    tempPW = []
    tempTS = ''
    flag_hashes = False
    flag_dashes = False
    flag_equals = False
    for line in fileList:
        if line.startswith('#################'):
            if tempTS:
                pwArray.append(['\n'.join(tempLabel), '\n'.join(tempPW), tempTS])
            else:
                pwArray.append(['\n'.join(tempLabel), '\n'.join(tempPW)])
            tempLabel = []
            flag_hashes, flag_equals, flag_dashes = True, False, False
        elif line.startswith('==='):
            tempTS = ''
            flag_hashes, flag_equals, flag_dashes = False, True, False
        elif line.startswith('---'):
            tempPW = []
            flag_hashes, flag_equals, flag_dashes = False, False, True
        else:
            if flag_hashes:
                tempLabel.append(line)
            elif flag_dashes:
                tempPW.append(line)
            elif flag_equals:
                tempTS = line.split('=')[-1].strip()
                if tempTS == '<none>':
                    tempTS = ''
    pwArray.append(['\n'.join(tempLabel), '\n'.join(tempPW), tempTS])
    del pwArray[0]
    #for iLabel, iPW, iTS in pwArray:
    for items in pwArray:
        aesObj._gen_keyiv_from_urandom()
        key_enc_b64str = Manager._encryptAESkeyiv(aesObj.aesKey, aesObj.aesIV)
        newPW_enc = Manager._encryptText(items[1], aesObj)
        if len(items) > 2:
            newTS_enc = Manager._encryptText(items[2], aesObj)
            Manager.pws.append([items[0], key_enc_b64str, newPW_enc, newTS_enc])
        else:
            Manager.pws.append([items[0], key_enc_b64str, newPW_enc])
        aesObj.reset()
    Manager.savePWsToFile()
    print("Password db file created.")

if __name__ == "__main__":
    main()
