import sqlite3


class BenchmarkTest00005:
    def __init__(self, data: str) -> None:                        # Source
        """Initialize benchmark test with data."""
        self.data = data                             # Taint Propagation

    def execute(self) -> None:
        connection = sqlite3.connect("example.db")
        cursor = connection.cursor()
        cursor.executescript(self.data)               # Class attribute access to taint
        connection.commit()
        connection.close()

