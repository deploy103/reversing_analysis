// Frida template for validating Reverse Researcher hypotheses.
// Usage: frida -f ./sample.exe -l hook_template.js --no-pause

const targets = [
  "IsDebuggerPresent",
  "CheckRemoteDebuggerPresent",
  "strcmp",
  "strncmp",
  "memcmp",
  "CryptDecrypt",
  "BCryptDecrypt",
  "send",
  "recv"
];

function hookExport(name) {
  const address = Module.findExportByName(null, name);
  if (!address) return;

  Interceptor.attach(address, {
    onEnter(args) {
      this.name = name;
      this.args = [];
      for (let i = 0; i < 4; i++) {
        this.args.push(args[i]);
      }
      send({ type: "enter", name, args: this.args.map(String) });
    },
    onLeave(retval) {
      send({ type: "leave", name: this.name, retval: retval.toString() });
    }
  });
}

for (const name of targets) {
  hookExport(name);
}

