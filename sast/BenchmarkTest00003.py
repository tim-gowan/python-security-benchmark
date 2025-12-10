import os


class BenchmarkTest00003:
    def __init__(self, data: str) -> None:
        """Initialize benchmark test with data."""
        self.data = data
        self.execute(data)

    def execute(self, data: str) -> None:
        os.system(data)

