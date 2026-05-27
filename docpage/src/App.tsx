import { HashRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import OverviewPage from './pages/OverviewPage'
import ArchitecturePage from './pages/ArchitecturePage'
import ApiPage from './pages/ApiPage'
import DriverPage from './pages/DriverPage'
import SecurityPage from './pages/SecurityPage'
import QuickStartPage from './pages/QuickStartPage'
import CloudPlatformPage from './pages/CloudPlatformPage'
import LocalManagerPage from './pages/LocalManagerPage'
import FrontendPage from './pages/FrontendPage'
import DatabasePage from './pages/DatabasePage'
import CryptoFlowPage from './pages/CryptoFlowPage'
import RoadmapPage from './pages/RoadmapPage'
import ChangelogPage from './pages/ChangelogPage'

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<HomePage />} />
          <Route path="overview" element={<OverviewPage />} />
          <Route path="architecture" element={<ArchitecturePage />} />
          <Route path="quickstart" element={<QuickStartPage />} />
          <Route path="api" element={<ApiPage />} />
          <Route path="driver" element={<DriverPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="cloud-platform" element={<CloudPlatformPage />} />
          <Route path="local-manager" element={<LocalManagerPage />} />
          <Route path="frontend" element={<FrontendPage />} />
          <Route path="database" element={<DatabasePage />} />
          <Route path="crypto-flow" element={<CryptoFlowPage />} />
          <Route path="roadmap" element={<RoadmapPage />} />
          <Route path="changelog" element={<ChangelogPage />} />
        </Route>
      </Routes>
    </HashRouter>
  )
}
