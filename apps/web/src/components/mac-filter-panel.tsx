import { LoaderCircle, Shield } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import type { MacFilterState } from "@ip-guard/electron";

export function MacFilterPanel() {
  const bridge = window.desktop;
  const [state, setState] = useState<MacFilterState>({
    phase: "unavailable",
    message: "正在检查本机签名和系统扩展",
  });
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!bridge) return;
    let alive = true,
      pending = false;
    const refresh = async () => {
      if (pending) return;
      pending = true;
      try {
        const reply = await bridge.invoke({ action: "mac-filter:status" });
        if (alive && reply.macFilter) setState(reply.macFilter);
      } catch (error) {
        if (alive)
          setState({
            phase: "error",
            message: error instanceof Error ? error.message : "系统过滤状态读取失败",
          });
      } finally {
        pending = false;
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [bridge]);
  const enabled = state.phase === "enabled";
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>
          <Shield size={18} /> macOS 系统网络过滤 · 实验功能
        </h2>
        <span>
          {enabled
            ? "策略通道已确认"
            : state.phase === "approval"
              ? "等待系统授权"
              : "尚未确认启用"}
        </span>
      </div>
      <div className="filter-body">
        <p role="status">{state.message}</p>
        <p className="field-hint">
          完成 Developer ID
          签名和描述文件配置后，可过滤已开启防护的应用包，包括从原快捷方式启动的实例。按
          Claude／ChatGPT 各自的 IP
          结果授权；守护失联或许可过期时拒绝已登记应用的网络。此功能不拦截应用本身的启动，代理代发连接及真实网络切换仍需本机验证。
        </p>
        <p className="field-hint">
          关闭“获取不到 IP
          时自动结束”可保留受控进程，但系统过滤器仍拒绝未确认出口的网络。关闭本过滤器后，浏览器插件和受控启动继续独立工作。
        </p>
        <button
          className="btn"
          disabled={!bridge || busy || state.phase === "unavailable"}
          onClick={async () => {
            if (!bridge) return;
            setBusy(true);
            try {
              const reply = await bridge.invoke({ action: "mac-filter:set", enabled: !enabled });
              if (reply.macFilter) setState(reply.macFilter);
            } catch (error) {
              toast.error(error instanceof Error ? error.message : "系统过滤操作失败");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? <LoaderCircle size={15} className="spin" /> : <Shield size={15} />}
          {enabled ? "关闭系统过滤" : "启用并进行系统授权"}
        </button>
      </div>
    </section>
  );
}
