import {
  browserStateSchema,
  formatIPText,
  protectedService,
  selectedServices,
  services,
  shouldBlockUrl,
} from "@ip-guard/electron";

import "./style.css";

const app = document.getElementById("app");
if (!app) throw new Error("Missing page root");
const blocked = document.body.dataset.view === "blocked";
app.innerHTML = `<header><span class="brand">IP Guard <small>CLAUDE / CHATGPT</small></span><div class="header-actions"><button id="ip-visibility" class="quiet" aria-label="显示 IP 地址" title="显示 IP 地址" aria-pressed="false"></button><button id="theme" class="quiet" aria-label="切换深浅主题">◐</button></div></header>
<label class="service-choice" for="service">查看服务<select id="service"><option value="claude">Claude</option><option value="chatgpt">ChatGPT</option></select></label>
<div class="scene"><svg class="shield" viewBox="0 0 48 48" fill="none" aria-hidden="true"><path d="M24 6 39 12v12c0 9-7 15-15 18C16 39 9 33 9 24V12Z"/><path class="tick" d="m17 24 5 5 10-11"/></svg></div>
<h1 id="status" role="status">连接中</h1><p id="reason"></p>
<dl><div><dt>所选服务出口 IPv4</dt><dd id="current">—</dd></div><div><dt>锁定 IPv4</dt><dd id="expected">—</dd></div></dl>
<ol id="steps"><li>守护连接<span></span></li><li>地址锁定<span></span></li><li>服务出口<span></span></li><li>IPv4 对照<span></span></li></ol>
<div class="actions"><button id="reconnect">重新连接</button><button id="open" class="primary" disabled>打开服务</button></div>
<footer><span id="time">等待守护结果</span><span id="version"></span></footer>`;
function element(id: string) {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing ${id}`);
  return found;
}
function button(id: string) {
  const found = element(id);
  if (!(found instanceof HTMLButtonElement)) throw new Error(`Missing button ${id}`);
  return found;
}
const open = button("open");
function serviceSelector() {
  const found = element("service");
  if (!(found instanceof HTMLSelectElement)) throw new Error("Missing service selector");
  return found;
}
const selector = serviceSelector();
let originalTarget: URL | undefined;
try {
  const value = new URLSearchParams(location.search).get("target");
  if (value) {
    const url = new URL(value);
    if (url.protocol === "https:" && protectedService(url.href)) originalTarget = url;
  }
} catch {
  /* Invalid destinations fall back to the selected service's home page. */
}
const requestedService = new URLSearchParams(location.search).get("service");
let chosen =
  Boolean(originalTarget) || requestedService === "claude" || requestedService === "chatgpt";
selector.value = originalTarget
  ? (protectedService(originalTarget.href) ?? "claude")
  : requestedService === "chatgpt"
    ? "chatgpt"
    : "claude";
const selected = () => (selector.value === "chatgpt" ? "chatgpt" : "claude");
const destination = () =>
  originalTarget && protectedService(originalTarget.href) === selected()
    ? originalTarget.href
    : `https://${services[selected()].domains[0]}/`;
selector.addEventListener("change", () => {
  chosen = true;
  void render();
});
document.documentElement.dataset.theme =
  localStorage.getItem("theme") ??
  (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
element("theme").addEventListener("click", () => {
  const value = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = value;
  localStorage.setItem("theme", value);
});
let permitted = false;
let ipsVisible = false;
function updatePrivacyButton() {
  const control = element("ip-visibility");
  const label = ipsVisible ? "隐藏 IP 地址" : "显示 IP 地址";
  control.setAttribute("aria-label", label);
  control.setAttribute("title", label);
  control.setAttribute("aria-pressed", String(ipsVisible));
  control.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>${ipsVisible ? '<path d="m3 3 18 18"/>' : ""}</svg>`;
}
element("ip-visibility").addEventListener("click", () => {
  ipsVisible = !ipsVisible;
  updatePrivacyButton();
  void render();
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    ipsVisible = false;
    updatePrivacyButton();
    void render();
  }
});
updatePrivacyButton();
async function render() {
  const saved = await chrome.storage.session.get(["state", "receivedAt"]);
  const parsed = browserStateSchema.safeParse(saved.state);
  const state = parsed.success ? parsed.data : undefined;
  const age = typeof saved.receivedAt === "number" ? Date.now() - saved.receivedAt : Infinity;
  const fresh = age >= 0 && age < 3500;
  if (!chosen && state) selector.value = state.service === "chatgpt" ? "chatgpt" : "claude";
  const protectedHere = !state || selectedServices(state.service).includes(selected());
  const phase = fresh && state ? state.phase : "offline";
  permitted = Boolean(state && !shouldBlockUrl(destination(), state, fresh));
  open.textContent = `${blocked ? "返回" : "打开"} ${services[selected()].name}`;
  document.body.dataset.phase = phase;
  element("status").textContent = !protectedHere
    ? "未启用防护"
    : permitted
      ? "校验通过"
      : phase === "checking"
        ? "正在检测"
        : "访问已阻断";
  element("reason").textContent = formatIPText(
    !protectedHere
      ? "此服务未选入防护；可在 IP Guard 的防护设置中启用"
      : fresh && state
        ? state.reason
        : "请运行 IP Guard 并准备浏览器扩展",
    ipsVisible,
  );
  element("current").textContent = formatIPText(
    protectedHere ? state?.currentIp || "—" : "未检测",
    ipsVisible,
  );
  element("expected").textContent = formatIPText(state?.expectedIp || "—", ipsVisible);
  element("version").textContent = state?.appVersion ? `v${state.appVersion}` : "";
  const date = state?.checkedAt ? new Date(state.checkedAt) : undefined;
  element("time").textContent =
    date && Number.isFinite(date.getTime())
      ? `最近检测 ${date.toLocaleTimeString("zh-CN", { hour12: false })}`
      : "等待守护结果";
  open.disabled = !permitted;
  const values = [
    protectedHere && phase !== "offline",
    protectedHere && phase !== "offline" && phase !== "unlocked",
    protectedHere && Boolean(state?.currentIp) && fresh,
    protectedHere && permitted,
  ];
  element("steps")
    .querySelectorAll("li")
    .forEach((step, index) => {
      step.dataset.done = String(values[index]);
      const marker = step.querySelector("span");
      if (marker) marker.textContent = values[index] ? "✓" : phase === "checking" ? "·" : "—";
    });
}
element("reconnect").addEventListener("click", () => {
  void chrome.runtime.sendMessage({ action: "reconnect" }).catch(() => {
    element("reason").textContent = "扩展后台未连接，请重新加载扩展";
  });
});
open.addEventListener("click", async () => {
  await render();
  if (!permitted) return;
  const target = destination();
  if (blocked) location.replace(target);
  else void chrome.tabs.create({ url: target });
});
chrome.storage.onChanged.addListener(() => void render());
setInterval(() => void render(), 1000);
void render();
