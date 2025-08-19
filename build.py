import PyInstaller.__main__ as pyinstaller


"""Set up the arguments required by PyInstaller to build the Network
Packet Sniffer binary."""
pyinstaller.run(("packet_sniffer/core.py", "--onefile"))
