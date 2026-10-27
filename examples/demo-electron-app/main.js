// A tiny Electron-style main process — packed into .asar to demo Trinetra's
// packaged-app reconstruction route. Our own code, safe to analyze.

function createWindow(options) {
  const defaults = { width: 1024, height: 768, webPreferences: { contextIsolation: true } };
  return { ...defaults, ...options };
}

function registerHandlers(ipc) {
  ipc.handle("ping", () => "pong");
  ipc.handle("version", () => "1.0.0");
}

function loadSettings(store) {
  return store.get("settings") || { theme: "system", telemetry: false };
}

function main(app, ipc, store) {
  app.whenReady().then(() => {
    const win = createWindow({ title: "Demo" });
    registerHandlers(ipc);
    const settings = loadSettings(store);
    return { win, settings };
  });
}

export { createWindow, registerHandlers, loadSettings, main };
