from .constants import S_BOX, INV_S_BOX

class State:

    def __init__(self, data_block: bytes):
        if len(data_block) != 16:
            raise ValueError("Data block must be 16 bytes long.")

        self.matrix = [[0] * 4 for _ in range(4)]
        for row in range(4):
            for col in range(4):
                self.matrix[row][col] = data_block[col * 4 + row]

    def __repr__(self) -> str:
        return "\n".join(
            " ".join(f"{byte:02x}" for byte in row)
            for row in self.matrix
        )

    def sub_bytes(self):
        for row in range(4):
            for col in range(4):
                self.matrix[row][col] = S_BOX[self.matrix[row][col]]

    def inv_sub_bytes(self):
        for row in range(4):
            for col in range(4):
                self.matrix[row][col] = INV_S_BOX[self.matrix[row][col]]

    def shift_rows(self):
        for row in range(1, 4):
            self.matrix[row] = self.matrix[row][row:] + self.matrix[row][:row]
            
    def inv_shift_rows(self):
        for row in range(1, 4):
            self.matrix[row] = self.matrix[row][-row:] + self.matrix[row][:-row]

    def gmul(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if high_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    def mix_columns(self):
        xtime = lambda x: ((x << 1) ^ 0x1b) & 0xFF if x & 0x80 else (x << 1)
        for col in range(4):
            s0 = self.matrix[0][col]
            s1 = self.matrix[1][col]
            s2 = self.matrix[2][col]
            s3 = self.matrix[3][col]
            self.matrix[0][col] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
            self.matrix[1][col] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
            self.matrix[2][col] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
            self.matrix[3][col] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)

    def inv_mix_columns(self):
        gmul = self._gmul
        for col in range(4):
            s0 = self.matrix[0][col]
            s1 = self.matrix[1][col]
            s2 = self.matrix[2][col]
            s3 = self.matrix[3][col]
            self.matrix[0][col] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09)
            self.matrix[1][col] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d)
            self.matrix[2][col] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b)
            self.matrix[3][col] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e)

    def _gmul(self, a, b):
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            high_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if high_bit_set:
                a ^= 0x1b
            b >>= 1
        return result

    def add_round_key(self, round_key):
        for row in range(4):
            for col in range(4):
                self.matrix[row][col] ^= round_key[col * 4 + row]
