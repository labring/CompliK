import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import { BansPage } from "./pages/BansPage";
import { CommitmentsPage } from "./pages/CommitmentsPage";
import { ConfigsPage } from "./pages/ConfigsPage";
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
        <Route path="/namespaces/:namespace" element={<NamespaceDetailPage />} />
        <Route path="/violations" element={<ViolationsPage />} />
        <Route path="/configs" element={<ConfigsPage />} />
        <Route path="/commitments" element={<CommitmentsPage />} />
        <Route path="/bans" element={<BansPage />} />
        <Route path="/unbans" element={<UnbansPage />} />
      </Route>
    </Routes>
  );
}
