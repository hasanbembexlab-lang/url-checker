const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const windowsPython = path.join(root, ".venv", "Scripts", "python.exe");
const unixPython = path.join(root, ".venv", "bin", "python");
const python = process.env.PYTHON || (
  process.platform === "win32" && fs.existsSync(windowsPython)
    ? windowsPython
    : process.platform !== "win32" && fs.existsSync(unixPython)
      ? unixPython
      : process.platform === "win32" ? "python" : "python3"
);
const env = { ...process.env, PYTHONIOENCODING: process.env.PYTHONIOENCODING || "utf-8" };

function runPython(args, label) {
  const result = spawnSync(python, args, { cwd: root, env, stdio: "inherit" });
  if (result.error) {
    throw new Error(`Could not ${label}: ${result.error.message}`);
  }
  return result.status;
}

function getHealth(port) {
  return new Promise((resolve) => {
    const request = http.get({ hostname: "127.0.0.1", port, path: "/api/health", timeout: 1000 }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => {
        try {
          const health = JSON.parse(body);
          resolve(response.statusCode === 200 && health.status === "ok" ? health : null);
        } catch {
          resolve(null);
        }
      });
    });
    request.on("timeout", () => request.destroy());
    request.on("error", () => resolve(null));
  });
}

function isPortAvailable(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", (error) => {
      if (error.code === "EADDRINUSE" || error.code === "EACCES") {
        resolve(false);
      } else {
        reject(error);
      }
    });
    server.listen({ host: "127.0.0.1", port }, () => {
      server.close((error) => error ? reject(error) : resolve(true));
    });
  });
}

function requestedPort(args) {
  const flagIndex = args.findIndex((arg) => arg === "--port" || arg.startsWith("--port="));
  if (flagIndex === -1) return { port: 8000, explicit: false };
  const value = args[flagIndex].startsWith("--port=")
    ? args[flagIndex].slice("--port=".length)
    : args[flagIndex + 1];
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port "${value}". Choose a port between 1 and 65535.`);
  }
  return { port, explicit: true };
}

async function main() {
  const userArgs = process.argv.slice(2);
  const requested = requestedPort(userArgs);
  let port = requested.port;

  if (!(await isPortAvailable(port))) {
    const health = await getHealth(port);
    if (health?.playwright_compatible === true) {
      console.log(`Website Diagnostic Monitor is already running at http://127.0.0.1:${port}`);
      return;
    }
    if (requested.explicit) {
      const reason = health?.status === "ok"
        ? "The existing server uses an incompatible Windows event loop."
        : "Another process is using that port.";
      throw new Error(`${reason} Stop it or choose another port with --port.`);
    }
    if (health?.status === "ok") {
      console.log(`The server on port ${port} cannot run Playwright; starting a compatible server on another port.`);
    }
    const firstPort = port;
    while (port < 65535 && !(await isPortAvailable(port))) {
      port += 1;
    }
    if (port === 65535 && !(await isPortAvailable(port))) {
      throw new Error(`No available port found starting at ${firstPort}.`);
    }
    console.log(`Port ${firstPort} is in use; using available port ${port} instead.`);
  }

  if (runPython(["-c", "import fastapi, uvicorn, playwright, numpy, requests, dns, PIL"], "check Python dependencies") !== 0) {
    console.log("Installing missing Python dependencies from requirements.txt...");
    if (runPython(["-m", "pip", "install", "-r", "requirements.txt"], "install Python dependencies") !== 0) {
      process.exit(1);
    }
  }

  console.log("Checking Playwright Chromium...");
  if (runPython(["-m", "playwright", "install", "chromium"], "install Playwright Chromium") !== 0) {
    process.exit(1);
  }

  const uvicornArgs = ["-m", "uvicorn", "monitor:app"];
  if (process.platform !== "win32") {
    uvicornArgs.push("--reload");
  } else {
    console.log("Windows uses the Proactor event loop required by Playwright; automatic reload is disabled.");
  }
  uvicornArgs.push(...userArgs);
  if (!requested.explicit) {
    uvicornArgs.push("--port", String(port));
  }
  console.log(`Starting Website Diagnostic Monitor at http://127.0.0.1:${port}`);
  const status = runPython(uvicornArgs, "start the development server");
  process.exit(status ?? 1);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
