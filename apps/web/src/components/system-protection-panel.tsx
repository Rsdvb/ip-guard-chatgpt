import { LoaderCircle, Shield } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import type { SystemProtectionState } from "@ip-guard/electron";

export function SystemProtectionPanel({ platform }: { platform: "darwin" | "linux" }) {
  const bridge = window.desktop;
  const [state, setState] = useState<SystemProtectionState>({
    phase: "unavailable",
    message: "正在检查本机签名和系统扩展",
  });
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!bridge) return;
    let alive = true,
      pending = false;
    const refresh = async () => {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const reply = await bridge.invoke({ action: "system:status" });
        if (alive && reply.systemProtection) setState(reply.systemProtection);
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
    const unsubscribe = bridge.subscribe((snapshot) => {
      if (alive && snapshot.systemProtection) setState(snapshot.systemProtection);
    });
    const timer = setInterval(() => void refresh(), 15000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      alive = false;
      clearInterval(timer);
      unsubscribe();
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [bridge]);
  const enabled = state.active ?? state.phase === "enabled";
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>
          <Shield size={18} /> {platform === "linux" ? "Ubuntu" : "macOS"} 系统防护 · 测试版
        </h2>
        <span>
          {state.phase === "enabled"
            ? "策略通道已确认"
            : state.phase === "approval"
              ? "等待系统或策略确认"
              : "尚未确认启用"}
        </span>
      </div>
      <div className="filter-body">
        <p role="status">{state.message}</p>
        <p className="field-hint">
          {platform === "linux"
            ? "安装 DEB 并完成管理员授权后，原快捷方式和终端入口也会校验启动许可，并在内核过滤已登记程序的连接。首次启用前请关闭目标程序。"
            : "完成 Developer ID 签名与系统授权后，已登记的 .app 和原生 CLI 从原入口打开时，也按独立 IP 结果过滤网络和处理停止策略。解释器脚本继续使用受控启动器。系统扩展的实际效果仍需在你的 Mac 上授权验证。"}
        </p>
        <p className="field-hint">
          Claude／ChatGPT 各自锁定、暂停和阻断。关闭“获取不到 IP
          时自动结束”可保留进程，系统层仍拒绝未确认出口的网络。关闭系统防护会停止系统组件登记的程序；网页和受控启动继续工作。
        </p>
        <button
          className="btn"
          disabled={!bridge || busy || state.phase === "unavailable"}
          onClick={async () => {
            if (!bridge) return;
            setBusy(true);
            try {
              const reply = await bridge.invoke({ action: "system:set", enabled: !enabled });
              if (reply.systemProtection) setState(reply.systemProtection);
            } catch (error) {
              toast.error(error instanceof Error ? error.message : "系统过滤操作失败");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? <LoaderCircle size={15} className="spin" /> : <Shield size={15} />}
          {enabled ? "停止程序并关闭系统防护" : "启用并进行系统授权"}
        </button>
      </div>
    </section>
  );
}
