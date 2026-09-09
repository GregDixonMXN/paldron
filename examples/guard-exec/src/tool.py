from pathlib import Path

Path("src/out.txt").write_text("via guard\n")
print("tool done")
