# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class WritesExe(Signature):
    name = "writes_exe"
    description = "Writes a Windows executable on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Jack28"]
    minimum = "0.5"

    enabled = True

    def run(self):
        subject = self.results["behavior"]["summary"]["write_files"]
        match = self._check_value(pattern=".*\\.exe$", subject=subject, regex=True)

        if match:
            self.data.append({"file": match})
            return True

        return False
