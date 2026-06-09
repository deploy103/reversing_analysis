# Integrations

These scripts export evidence from reverse engineering tools into JSON that can be fed into Reverse Researcher reports.

Current files:

- `ida/revbot_export.py`: IDAPython exporter.
- `ghidra/revbot_export.py`: Ghidra headless/script-manager exporter.
- `frida/hook_template.js`: Dynamic validation hook template.
- `r2/export.r2`: radare2 command recipe.

The core CLI already runs command-line collectors when available. These integration scripts cover GUI or lab workflows where the analyst opens the binary manually and exports richer evidence.

