$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
python build_payload.py final_exploit -o exploit.bin
Copy-Item exploit.bin payload\exploit.bin -Force
python build_payload.py local_exploit -o local_exploit.bin | Out-Null
Copy-Item local_exploit.bin payload\local_exploit.bin -Force
