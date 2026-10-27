import { LoaderCircle, Save, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { serviceSchema } from "@ip-guard/electron";
import type { ProtectedApp } from "@ip-guard/electron";

export function EditAppDialog({
  app,
  busy,
  available,
  onClose,
  onSave,
}: {
  app: ProtectedApp;
  busy: boolean;
  available: boolean;
  onClose: () => void;
  onSave: (value: Pick<ProtectedApp, "name" | "arguments" | "service">) => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const argsInput = useRef<HTMLInputElement>(null);
  const [service, setService] = useState(app.service);
  const [name, setName] = useState(app.name);
  const [args, setArgs] = useState(app.arguments);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    argsInput.current?.focus();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="guard-dialog"
      aria-labelledby="edit-app-title"
      onCancel={(event) => {
        if (busy) event.preventDefault();
        else onClose();
      }}
      onClick={(event) => {
        if (!busy && event.target === event.currentTarget) onClose();
      }}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy && available && name.trim()) void onSave({ name, arguments: args, service });
        }}
      >
        <header>
          <h2 id="edit-app-title">编辑程序</h2>
          <button
            type="button"
            className="icon-btn"
            aria-label="关闭编辑"
            disabled={busy}
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </header>
        <div className="dialog-fields">
          <div className="form-row">
            <label htmlFor="edit-app-service">归属服务</label>
            <select
              id="edit-app-service"
              value={service}
              disabled={busy || app.enabled}
              onChange={(event) => setService(serviceSchema.parse(event.target.value))}
            >
              <option value="claude">Claude</option>
              <option value="chatgpt">ChatGPT</option>
            </select>
            <span className="muted">修改归属前请先解除该程序防护。</span>
          </div>
          <div className="form-row">
            <label htmlFor="edit-app-path">程序路径</label>
            <input id="edit-app-path" value={app.path} title={app.path} readOnly />
          </div>
          <div className="form-row">
            <label htmlFor="edit-app-name">显示名称</label>
            <input
              id="edit-app-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              maxLength={100}
              required
              disabled={busy}
            />
          </div>
          <div className="form-row">
            <label htmlFor="edit-app-args">
              启动参数 <span className="muted">下次从 IP Guard 启动时生效</span>
            </label>
            <input
              ref={argsInput}
              id="edit-app-args"
              value={args}
              onChange={(event) => setArgs(event.target.value)}
              maxLength={4096}
              disabled={busy}
            />
          </div>
        </div>
        <footer>
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            取消
          </button>
          <button
            type="submit"
            className="btn primary"
            disabled={busy || !available || !name.trim()}
          >
            {busy ? <LoaderCircle size={15} className="spin" /> : <Save size={15} />}保存修改
          </button>
        </footer>
      </form>
    </dialog>
  );
}
