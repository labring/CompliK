import { ArrowRight, RefreshCw } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAppData } from "../contexts/AppDataContext";
import { Button, PageHeader, StatusPill, SurfaceCard } from "../components/ui";

export function OverviewPage() {
  const navigate = useNavigate();
  const { latestActions, latestViolations, quickLinks, stats } = useAppData();

  return (
    <div className="page-container">
      <PageHeader
        kicker="Overview"
        title="合规总览"
        description="先看风险数量和最近动态，再进入具体 namespace 或记录页处理。"
        actions={<Button variant="secondary"> <RefreshCw size={16} /> 刷新 </Button>}
      />

      <section className="stat-grid">
        {stats.map((item) => (
          <SurfaceCard
            className="stat-card clickable"
            key={item.label}
            padded={false}
          >
            <button
              className="table-row-button"
              onClick={() => item.targetPath && navigate(item.targetPath)}
              type="button"
            >
              <div className="stat-card">
                <div className="stat-label">{item.label}</div>
                <div className="stat-value-row">
                  <div className="stat-value">{item.value}</div>
                  <div className={`stat-delta tone-${item.tone}`}>{item.delta}</div>
                </div>
                <div className="muted-text">{item.description}</div>
              </div>
            </button>
          </SurfaceCard>
        ))}
      </section>

      <section className="split-grid">
        <SurfaceCard>
          <div className="section-title-row">
            <div>
              <h2 className="section-title">最新违规</h2>
              <p className="section-subtitle">点击 namespace 直接进入详情页</p>
            </div>
            <Button variant="ghost" onClick={() => navigate("/violations")}>
              查看全部
            </Button>
          </div>
          <div className="activity-list">
            {latestViolations.map((item) => (
              <div className="activity-item" key={item.id}>
                <div className="activity-primary">
                  <button
                    className="namespace-link table-row-button"
                    onClick={() => navigate(item.targetPath ?? "/violations")}
                    type="button"
                  >
                    {item.namespace}
                    <ArrowRight size={14} />
                  </button>
                  <div>{item.summary}</div>
                </div>
                <div style={{ display: "grid", gap: 8, justifyItems: "end" }}>
                  <StatusPill tone={item.tone}>{item.tone === "danger" ? "高风险" : "待核查"}</StatusPill>
                  <span className="muted-text">{item.time}</span>
                </div>
              </div>
            ))}
          </div>
        </SurfaceCard>

        <SurfaceCard>
          <div className="section-title-row">
            <div>
              <h2 className="section-title">最新封禁与解封</h2>
              <p className="section-subtitle">记录录入与处理动作按时间倒序展示</p>
            </div>
          </div>
          <div className="activity-list">
            {latestActions.map((item) => (
              <div className="activity-item" key={item.id}>
                <div className="activity-primary">
                  <button
                    className="namespace-link table-row-button"
                    onClick={() => navigate(item.targetPath ?? "/overview")}
                    type="button"
                  >
                    {item.namespace}
                    <ArrowRight size={14} />
                  </button>
                  <div>{item.summary}</div>
                </div>
                <div style={{ display: "grid", gap: 8, justifyItems: "end" }}>
                  <StatusPill tone={item.tone}>
                    {item.tone === "success" ? "已解封" : item.tone === "warn" ? "已封禁" : "已更新"}
                  </StatusPill>
                  <span className="muted-text">{item.time}</span>
                </div>
              </div>
            ))}
          </div>
        </SurfaceCard>
      </section>

      <section className="quick-links-grid">
        {quickLinks.map((item) => (
          <SurfaceCard className="quick-link-card" key={item.title}>
            <div>
              <h2 className="section-title">{item.title}</h2>
              <p className="section-subtitle">{item.description}</p>
            </div>
            <div className="button-row">
              <Button variant="secondary" onClick={() => navigate(item.targetPath)}>
                进入页面
              </Button>
            </div>
          </SurfaceCard>
        ))}
      </section>
    </div>
  );
}
