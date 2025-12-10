import subprocess as sp


class BenchmarkTest00001:
    def __init__(self, data: str) -> None:
        """Initialize benchmark test with data."""
        self.data = data
        self.process()                    # Command Injection Sink.

    def process(self) -> None:
        sp.run(self.data, shell=True)     # Command Injection Sink.

    def execute(self, data: str) -> None:
        sp.Popen(data, shell=True)        # Command Injection Sink.

def process_func(data: str) -> None:
    sp.run(data, shell=True)              # Command Injection Sink.
