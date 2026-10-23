const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const frontendPath = path.join(root, "frontend", "index.html");
const html = fs.readFileSync(frontendPath, "utf8");
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];

if (scripts.length === 0) {
  throw new Error("No frontend JavaScript was found in frontend/index.html.");
}

for (const [index, script] of scripts.entries()) {
  new vm.Script(script[1], { filename: `frontend/index.html inline script ${index + 1}` });
}
console.log("Frontend JavaScript syntax OK.");

const python = process.platform === "win32" ? "python" : "python3";
const result = spawnSync(python, ["-m", "compileall", "-q", "monitor.py"], {
  cwd: root,
  encoding: "utf8",
});

if (result.error) {
  throw new Error(`Could not run ${python} to compile the Python backend: ${result.error.message}`);
}
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}

console.log("Python backend syntax OK.");
