import {
  AlertTriangle,
  Ban,
  BriefcaseBusiness,
  FileCog,
  FileText,
  LayoutGrid,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { cn } from "../lib/utils";

const navItems = [
  { label: "总览", path: "/overview", icon: LayoutGrid },
  { label: "命名空间详情", path: "/namespaces/prod-finance", icon: ShieldCheck },
  { label: "违规中心", path: "/violations", icon: AlertTriangle },
  { label: "项目配置", path: "/configs", icon: FileCog },
  { label: "承诺书管理", path: "/commitments", icon: FileText },
  { label: "封禁记录", path: "/bans", icon: Ban },
  { label: "解封记录", path: "/unbans", icon: BriefcaseBusiness },
];

export function AppLayout() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <span className="page-kicker">CompliK Admin</span>
          <h2 className="brand-title">合规管理后台</h2>
          <p className="brand-subtitle">
            统一查看 namespace 风险、封禁与承诺书记录。
          </p>
        </div>
        <nav className="nav-list" aria-label="主导航">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                className={({ isActive }) => cn("nav-item", isActive && "active")}
                key={item.path}
                to={item.path}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
        <p className="mobile-nav-note">移动端仍保留同一套导航顺序，但页面会改成纵向堆叠。</p>
      </aside>
      <main className="main-shell">
        <Outlet />
      </main>
    </div>
  );
}
