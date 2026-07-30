import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import { AutobanPolicyPage } from "./pages/AutobanPolicyPage";
import { BansPage } from "./pages/BansPage";
import { CommitmentsPage } from "./pages/CommitmentsPage";
import { ConfigsPage } from "./pages/ConfigsPage";
import { DiscoveredPathsPage } from "./pages/DiscoveredPathsPage";
import { NamespaceDetailPage } from "./pages/NamespaceDetailPage";
import { OverviewPage } from "./pages/OverviewPage";
import { UnbansPage } from "./pages/UnbansPage";
import { ViolationsPage } from "./pages/ViolationsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Navigate replace to="/overview" />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/namespaces" element={<NamespaceDetailPage />} />
        <Route path="/namespaces/:namespace" element={<NamespaceDetailPage />} />
        <Route path="/discovered-paths" element={<DiscoveredPathsPage />} />
        <Route path="/violations" element={<ViolationsPage />} />
        <Route path="/autoban" element={<AutobanPolicyPage />} />
        <Route path="/configs" element={<ConfigsPage />} />
        <Route path="/commitments" element={<CommitmentsPage />} />
        <Route path="/bans" element={<BansPage />} />
        <Route path="/unbans" element={<UnbansPage />} />
      </Route>
    </Routes>
  );
}
