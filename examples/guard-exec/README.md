# guard exec fixture

The composition, copy-paste:

```sh
annalist run -- guard exec --policy policy.toml -- python3 src/tool.py
# exit 0, src/out.txt written, session recorded
```

A tool that writes `.env` instead exits 2 (`run produced .env`), and the
annalist session records the denial. Guard decides, annalist records.
