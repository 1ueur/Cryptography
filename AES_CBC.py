# AES CBC 단문 메시지 암/복호화
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as SHA

class myAES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        self.key = key[:16]

        # AES의 암호화를 수행하는 블록 크기는 128bit이기 때문에 초기화 벡터는 16byte 크기.
        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv = iv[:16]

    # 헤더 크기 16byte.
    def makeEnabled(self, plaintext):
        fillersize = 0
        textsize = len(plaintext)
        if textsize % 16 != 0:
            fillersize = 16 - textsize%16

        filler = '0' * fillersize
        header = '%d' %(fillersize)
        gap = 16 - len(header)
        header += '#' * gap

        return header + plaintext + filler
    
    def enc(self, plaintext):
        plaintext = self.makeEnabled(plaintext)
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        encmsg = aes.encrypt(plaintext.encode())
        return encmsg

    def dec(self, ciphertext):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        decmsg = aes.decrypt(ciphertext)

        header = decmsg[:16].decode() # 복호화된 정보 decmsg의 처음 16byte를 유니코드로 변환하고.
        fillersize = int(header.split('#')[0]) # header를 '#' 구분자로 분리하고, 분리된 값 중 첫 번째를 정수로 변환.(ex)12##############)
        if fillersize != 0:
            decmsg = decmsg[16:-fillersize] # fillersize는 '0' 문자의 개수, decmsg 16 - fillersize까지 슬라이싱 -> 원래의 정보 추출.
        else:
            decmsg = decmsg[16:]
        return decmsg

def main():
    keytext = 'samsjang'
    ivtext = '1234'
    msg = 'python3xab' # 16byte 배수

    myCipher = myAES(keytext, ivtext)
    ciphered = myCipher.enc(msg)
    deciphered = myCipher.dec(ciphered)

    print(f'ORIGINAL: {msg}')
    print(f'CIPHERED: {ciphered}')
    print(f'DECIPHERED: {deciphered}')

if __name__ == '__main__':
    main()
