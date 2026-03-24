from datetime import datetime


class PacketLogger:
    COLUMNS = [
        ("TIME", 21),
        ("DIR", 6),
        ("EVENT", 12),
        ("REASON", 24),
        ("TYPE", 10),
        ("SEQ", 8),
        ("CHECKSUM", 16),
        ("ACK_NUM", 8),
        ("DATA_LEN", 8),
    ]

    def __init__(self, log_path):
        self.log_path = log_path
        self.log_file = open(log_path, "w", encoding="utf-8")
        self.log_file.write(self._format_header() + "\n")
        self.log_file.write(self._format_separator() + "\n")
        self.log_file.flush()

    def _format_header(self):
        return "".join(f"{name:<{width}}" for name, width in self.COLUMNS).rstrip()

    def _format_separator(self):
        return "-" * len(self._format_header())

    def _format_row(self, values):
        return "".join(
            f"{str(values.get(name, '')):<{width}}" for name, width in self.COLUMNS
        ).rstrip()

    def log_drop(self, packet, reason):
        flds = packet.getFlds()
        row = {
            "TIME": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "DIR": "RECV",
            "EVENT": "DROP",
            "REASON": reason,
            "TYPE": flds.get("TYPE", ""),
            "SEQ": flds.get("SEQ", ""),
            "CHECKSUM": flds.get("CHECKSUM", ""),
            "ACK_NUM": flds.get("ACK_NUM", ""),
            "DATA_LEN": len(flds["DATA"]) if "DATA" in flds else "",
        }
        self.log_file.write(self._format_row(row) + "\n")
        self.log_file.flush()

    def log_send(self, packet):
        flds = packet.getFlds()
        row = {
            "TIME": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "DIR": "SEND",
            "EVENT": "SEND",
            "REASON": "",
            "TYPE": flds.get("TYPE", ""),
            "SEQ": flds.get("SEQ", ""),
            "CHECKSUM": flds.get("CHECKSUM", ""),
            "ACK_NUM": flds.get("ACK_NUM", ""),
            "DATA_LEN": len(flds["DATA"]) if "DATA" in flds else "",
        }
        self.log_file.write(self._format_row(row) + "\n")
        self.log_file.flush()

    def close(self):
        self.log_file.close()
