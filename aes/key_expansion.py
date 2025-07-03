from .constants import S_BOX

def key_expansion(key):
    assert len(key) == 16
    expanded = bytearray(key)
    rcon = 1
    for i in range(16, 176, 4):
        temp = expanded[i-4:i]
        if i % 16 == 0:
            temp = temp[1:] + temp[:1]
            temp = bytearray(S_BOX[b] for b in temp)
            temp[0] ^= rcon
            rcon = (rcon << 1) ^ (0x11b if rcon & 0x80 else 0)
        for j in range(4):
            expanded.append(expanded[i-16+j] ^ temp[j])
    return [bytes(expanded[i:i+16]) for i in range(0, 176, 16)] 