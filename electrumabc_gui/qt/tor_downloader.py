#!/usr/bin/env python3
#
# Electrum ABC - lightweight eCash client
# Copyright (C) 2023 The Electrum ABC developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import multiprocessing

import requests


class Downloader:
    """URL downloader designed to be run as a separate process and to communicate
    with the main process via a Queue.

    multiprocessing is used because of pythons multi-threading limitations, and
    because an alternative solution based on QNetworkAccessManager would not work
    for any HTTPS URL (SSL issues).

    The queue can be monitored for the following messages (as str objects):

      - "@started@"
      - "@HTTP status@ {status code} {reason}"
        (e.g "@HTTP status@ 200 OK")
      - "@content size@ {size in bytes}"
      - "@finished@"
    """

    def __init__(self, url: str, filename: str):
        self.url = url
        self.filename = filename

        self.queue = multiprocessing.Queue()

    def run_download(self):
        self.queue.put("@started@")
        r = requests.get(url)
        self.queue.put(f"@HTTP status@ {r.status_code} {r.reason}")
        self.queue.put(f"@content size@ {len(r.content)}")
        with open(self.filename, "wb") as f:
            f.write(r.content)
        self.queue.put("@finished@")


if __name__ == "__main__":
    # Code sample to better document the API
    import os
    import sys
    from pathlib import Path

    from PyQt5.QtCore import QTimer
    from PyQt5.QtWidgets import QApplication

    url = sys.argv[1]
    fname = sys.argv[2]

    dl_path = os.path.join(str(Path.home()), "test_dl")
    os.makedirs(dl_path, exist_ok=True)
    app = QApplication([])

    downloader = Downloader(url, os.path.join(dl_path, fname))
    process = multiprocessing.Process(target=downloader.run_download)

    timer = QTimer()

    def read_queue():
        while not downloader.queue.empty():
            msg = downloader.queue.get()
            print(msg)
            if msg == "@finished@":
                timer.stop()

    timer.timeout.connect(read_queue)
    timer.timeout.connect(lambda: print("."))

    process.start()
    # Read the queue every second
    timer.start(1000)

    app.exec_()
