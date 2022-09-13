# 3DES CBC 단문 메시지 암호화
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256 as SHA

# 3DES 암/복호화 메소드 정의
class myDES():
    def __init__(self, keytext, ivtext): # keytext: 암호 키 생성 문자열 ivtext: 초기화 벡터 문자열
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        # Pycryptodome에서 제공하는 3DES가 가지는 키의 크기는 16byte 또는 24byte. SHA256은 32byte 크기이기 때문에 16 or 24만큼 슬라이싱이 필요.
        self.key = key[:24]

        # CBC 모드 암호화. 3DES는 64bit 암호화 블록 크기를 가짐.(초기화 벡터도 반드시 64bit) 초기화 벡터로 8byte 할당.
        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv = iv[:8]

    # 인자로 받은 plaintext를 3DES로 암호화.
    def enc(self, plaintext):
        plaintext = make8String(plaintext)
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv) # 순서대로 암호키, 운영 모드, 초기화 벡터
        encmsg = des3.encrypt(plaintext.encode())
        return encmsg

    # 복호화.
    def dec(self, ciphertext):
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)
        decmsg = des3.decrypt(ciphertext)
        return decmsg

# 인자로 입력되는 문자열 msg의 길이를 8byte 배수로 만들기 위해 문자 '0'을 msg 마지막 부분에 추가해 주는 함수
def make8String(msg):
    msglen = len(msg)
    filler = ''
    if msglen % 8 != 0:
        filler = '0'*(8 - msglen%8)
    msg += filler
    return msg

def main():
    keytext = 'samsjang' # 암호키
    ivtext = '1234' # 초기화 벡터
    msg = 'python3xab' # 암호화하려는 메시지(메시지의 길이가 8byte의 배수여야 함. -> make8String()함수 사용)

    myCipher = myDES(keytext, ivtext)
    ciphered = myCipher.enc(msg)
    deciphered = myCipher.dec(ciphered)

    print(f'ORIGINAL: {msg}')
    print(f'CIPHERED: {ciphered}')
    print(f'DECIPHERED: {deciphered}')

if __name__ == '__main__':
    main()
        
        
    


