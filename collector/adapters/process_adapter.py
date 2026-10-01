import subprocess
from typing import Iterator


class ProcessAdapter:
    def __init__(self, executable="./ebpf/process/process_monitor"):
        self.executable = executable

    def stream_events(self) -> Iterator[str]:
        process = subprocess.Popen(
            ["sudo", "-n", self.executable],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        if process.stdout is None:
            return

        while True:
            line = process.stdout.readline()

            if not line:
                if process.poll() is not None:
                    break
                continue

            line = line.strip()

            if line:
                yield line

        process.stdout.close()
        process.wait()
