# ARC4 단문 메시지 암/복호화
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA256 as SHA

# 스트림 암호는 8bit 단위로 암호화를 수행하기 때문에 암호 블록 크기는 1byte.
class myARC4():
    def __init__(self, keytext):
        self.key = keytext.encode()
    
    def enc(self, plaintext):
        arc4 = ARC4.new(self.key) # ARC4는 운영 모드 ECB만 사용하기 때문에 초기화 벡터가 필요 없다.
        encmsg = arc4.encrypt(plaintext.encode())
        return encmsg

    def dec(self, ciphertext):
        arc4 = ARC4.new(self.key)
        decmsg = arc4.decrypt(ciphertext)
        return decmsg

def main():
    keytext = 'samsjang'
    msg = 'study arc4'

    myCipher = myARC4(keytext)
    ciphered = myCipher.enc(msg)
    deciphered = myCipher.dec(ciphered)

    print(f'ORIGINAL: {msg}')
    print(f'CIPHERED: {ciphered}')
    print(f'DECIPHERED: {deciphered}')

if __name__ == '__main__':
    main()

    
