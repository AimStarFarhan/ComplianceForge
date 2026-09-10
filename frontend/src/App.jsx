import { ToastProvider } from "./components/Toast";
import { ThemeProvider } from "./components/ThemeToggle";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { useEffect } from "react";
import { ensureLogin } from "./lib/api";
import ConsoleLayout from "./components/ConsoleLayout";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import ReportPreview from "./pages/ReportPreview";
import TrainingLoop from "./pages/TrainingLoop";
import UploadIngest from "./pages/UploadIngest";

export default function App() {
  useEffect(() => {
    ensureLogin().catch(() => {});
  }, []);

  return (
    <ThemeProvider>
      <ToastProvider>
        <BrowserRouter>
        <Routes>
          {/* Marketing landing page */}
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          {/* Embedded ComplianceForge console */}
          <Route path="/console" element={<ConsoleLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="devices" element={<Devices />} />
            <Route path="devices/:deviceId" element={<DeviceDetail />} />
            <Route path="training" element={<TrainingLoop />} />
            <Route path="upload" element={<UploadIngest />} />
            <Route path="reports" element={<ReportPreview />} />
          </Route>
          <Route path="*" element={<Landing />} />
        </Routes>
      </BrowserRouter>
      </ToastProvider>
    </ThemeProvider>
  );
}
