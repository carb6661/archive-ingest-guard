"""Create one original, benign sample ZIP under output; never overwrite a file."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from archiveguard.demo import MANIFEST, SAMPLE, make_zip, ordinary

directory = Path("output")
directory.mkdir(exist_ok=True)
with (directory / "synthetic.zip").open("xb") as target:
    target.write(make_zip([
        ordinary("controls/access.md", SAMPLE), ordinary("manifest.json", MANIFEST),
    ]))
print("Created output/synthetic.zip (synthetic content only; existing files are not overwritten).")
