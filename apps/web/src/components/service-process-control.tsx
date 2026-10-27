import { LoaderCircle, Square } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { serviceName } from "@ip-guard/electron";
import type { ProcessState, Service } from "@ip-guard/electron";

export function ServiceProcessControl({ service }: { service: Service }) {
  const name = serviceName(service);
  const bridge = window.desktop;
  const [state, setState] = useState<ProcessState>({
    phase: "unknown",
    service,
    count: 0,
    canStop: false,
    message: "",
    checkedAt: "",
  });
  const [loading, setLoading] = useState(Boolean(bridge));
  const [stopping, setStopping] = useState(false);
  const stoppingRef = useRef(false);
  const version = useRef(0);
  useEffect(() => {
    if (!bridge) return;
    let alive = true,
      pending = false;
    const refresh = async () => {
      if (pending || stoppingRef.current) return;
      pending = true;
      const current = ++version.current;
      try {
        const reply = await bridge.invoke({ action: "process:status", service });
        if (alive && current === version.current && reply.processes) setState(reply.processes);
      } catch {
        if (alive && current === version.current)
          setState({
            phase: "unknown",
            service,
            count: 0,
            canStop: false,
            message: "进程状态读取失败",
            checkedAt: "",
          });
      } finally {
        pending = false;
        if (alive) setLoading(false);
      }
    };
    void refresh();
    const visible = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    const timer = setInterval(visible, 3000);
    document.addEventListener("visibilitychange", visible);
    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [bridge, service]);
  const stop = async () => {
    if (!bridge || stoppingRef.current) return;
    stoppingRef.current = true;
    version.current++;
    setStopping(true);
    try {
      const reply = await bridge.invoke({ action: "process:stop", service });
      if (reply.processes) setState(reply.processes);
      if (!reply.cancelled && reply.processes?.phase === "stopped")
        toast.success(`${name} 进程树已停止`);
    } catch (error) {
      toast.error(
        (error instanceof Error ? error.message : "停止失败").replace(
          /^Error invoking remote method '[^']+': Error: /,
          "",
        ),
      );
      try {
        const reply = await bridge.invoke({ action: "process:status", service });
        if (reply.processes) setState(reply.processes);
      } catch {
        setState({
          phase: "unknown",
          service,
          count: 0,
          canStop: false,
          message: "进程状态暂未确认",
          checkedAt: "",
        });
      }
    } finally {
      stoppingRef.current = false;
      setStopping(false);
    }
  };
  const label = stopping
    ? "正在停止"
    : loading
      ? "检测中"
      : state.phase === "running"
        ? "运行中"
        : state.phase === "stopped"
          ? "未运行"
          : "状态未知";
  return (
    <div className="service-process-control" role="group" aria-label={`${name} 进程控制`}>
      <button
        type="button"
        className="btn service-process-stop"
        disabled={!bridge || !state.canStop || stopping || loading}
        title={state.message || `停止当前用户的 ${name} 进程树`}
        onClick={() => void stop()}
      >
        {stopping ? <LoaderCircle size={14} className="spin" /> : <Square size={13} />}停止 {name}{" "}
        进程树
      </button>
      <span
        className={`service-process-state ${state.phase}`}
        role="status"
        title={
          state.message ||
          (state.checkedAt
            ? `最近检测 ${new Date(state.checkedAt).toLocaleTimeString("zh-CN", { hour12: false })}`
            : "")
        }
      >
        <span className="tiny-dot" />
        {label}
      </span>
    </div>
  );
}
