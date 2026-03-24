class CircularByteBuffer:
    def __init__(self, capacity):
        self.buf = bytearray(capacity)
        self.capacity = capacity
        self.head = 0
        self.tail = 0
        self.count = 0

    def available_data(self):
        return self.count

    def available_space(self):
        return self.capacity - self.count

    def write(self, data):
        if len(data) > self.available_space():
            return False

        tail_write_len = min(len(data), self.capacity - self.tail)
        self.buf[self.tail:self.tail + tail_write_len] = data[:tail_write_len]

        wrap_write_len = len(data) - tail_write_len
        if wrap_write_len > 0:
            self.buf[0:wrap_write_len] = data[tail_write_len:]

        self.tail = (self.tail + len(data)) % self.capacity
        self.count += len(data)
        return True

    def read(self, n):
        n = min(n, self.count)

        head_read_len = min(n, self.capacity - self.head)
        data = bytes(self.buf[self.head:self.head + head_read_len])

        wrap_read_len = n - head_read_len
        if wrap_read_len > 0:
            data += bytes(self.buf[0:wrap_read_len])

        self.head = (self.head + n) % self.capacity
        self.count -= n
        return data
