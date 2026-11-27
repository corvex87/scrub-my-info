# scrub my info

Redacts secrets and personal info from a text file before you paste it into an AI.
Each value becomes a stable placeholder (`[IP_1]`, `[SECRET_3]`, ...), and a legend maps the placeholders back to the real values.

- **Windows:** run `scrub_my_info.exe` (no Python needed)
- **From source:** `python scrub_my_info.py` (Python 3.12+, stdlib only)
- **Self-test:** `python scrub_my_info.py --test`

Catches: private keys (PEM and base64-wrapped), API keys (AWS, GitHub, Slack, OpenAI/Anthropic, Google, Stripe, Azure), password hashes,
`key=value` secrets and key/value pairs glued with no separator (config dumps), emails, IBANs, cards, codice fiscale, SSNs, IPv4/IPv6, MACs, UUIDs, phones,
usernames in paths, and Italian name/company/address fields.

It's regex-based, so names and hostnames only get hidden if you type them into the "also hide" box. Always review the output before sending it.
The legend contains the real values: keep it local.

Rebuild the exe:

```
python -m pip install pyinstaller
python -m PyInstaller --onefile --windowed --name scrub_my_info --distpath . scrub_my_info.py
```
