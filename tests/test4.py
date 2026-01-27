import base64

def is_base64(s: str) -> bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False


print(is_base64("AEtcMUA7Kx4CPD8YWBU/HwJGMUM=wer4"))
