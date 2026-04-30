import type {
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { X } from "lucide-react";
import { useEffect } from "react";
import { cn } from "../lib/utils";
import type { RiskTone } from "../types";

export function PageHeader({
  kicker,
  title,
  description,
  actions,
}: {
  kicker: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-title-block">
        <div className="page-kicker">{kicker}</div>
        <h1 className="page-title">{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {actions ? <div className="button-row">{actions}</div> : null}
    </header>
  );
}

export function Button({
  children,
  variant = "secondary",
  onClick,
  type = "button",
}: {
  children: ReactNode;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  onClick?: () => void;
  type?: "button" | "submit";
}) {
  return (
    <button className={cn("btn", `btn-${variant}`)} onClick={onClick} type={type}>
      {children}
    </button>
  );
}

export function SurfaceCard({
  children,
  className,
  padded = true,
}: {
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return <section className={cn("surface-card", padded && "padded", className)}>{children}</section>;
}

export function StatusPill({ tone, children }: { tone: RiskTone; children: ReactNode }) {
  return <span className={cn("pill", `pill-${tone}`)}>{children}</span>;
}

export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input className="input" {...props} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className="select" {...props} />;
}

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className, ...rest } = props;
  return <textarea className={cn("text-area", className)} {...rest} />;
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <h3 className="section-title" style={{ marginBottom: 8 }}>
        {title}
      </h3>
      <p className="muted-text" style={{ margin: 0 }}>
        {description}
      </p>
      {action ? <div className="button-row" style={{ justifyContent: "center", marginTop: 18 }}>{action}</div> : null}
    </div>
  );
}

export function Drawer({
  open,
  title,
  description,
  children,
  onClose,
}: {
  open: boolean;
  title: string;
  description: string;
  children: ReactNode;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <div className="drawer-shell">
        <aside className="drawer-panel">
          <div className="drawer-header">
            <div>
              <h2 className="panel-title">{title}</h2>
              <p className="panel-description">{description}</p>
            </div>
            <button className="icon-btn" onClick={onClose} type="button" aria-label="关闭详情">
              <X size={18} />
            </button>
          </div>
          {children}
        </aside>
      </div>
    </>
  );
}

export function Modal({
  open,
  title,
  description,
  children,
  onClose,
}: {
  open: boolean;
  title: string;
  description: string;
  children: ReactNode;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal-shell">
        <div className="modal-card">
          <div className="modal-header">
            <div>
              <h2 className="panel-title">{title}</h2>
              <p className="panel-description">{description}</p>
            </div>
            <button className="icon-btn" onClick={onClose} type="button" aria-label="关闭弹窗">
              <X size={18} />
            </button>
          </div>
          {children}
        </div>
      </div>
    </>
  );
}

export function DetailList({
  items,
}: {
  items: Array<{ label: string; value: ReactNode }>;
}) {
  return (
    <div className="details-grid">
      {items.map((item) => (
        <div className="detail-row" key={item.label}>
          <div className="detail-label">{item.label}</div>
          <div className="detail-value">{item.value}</div>
        </div>
      ))}
    </div>
  );
}

export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel = "确认删除",
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal open={open} title={title} description={description} onClose={onClose}>
      <div className="button-row">
        <Button variant="danger" onClick={onConfirm}>
          {confirmLabel}
        </Button>
        <Button variant="secondary" onClick={onClose}>
          取消
        </Button>
      </div>
    </Modal>
  );
}
