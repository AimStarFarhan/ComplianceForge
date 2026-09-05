import { ToastProvider } from "./components/Toast";
import Header from "./components/Header";
import Sidebar from "./components/Sidebar";
import Footer from "./components/Footer";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { useEffect } from "react";
import { ensureLogin } from "./lib/api";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Login from "./pages/Login";
import ReportPreview from "./pages/ReportPreview";
import TrainingLoop from "./pages/TrainingLoop";
import UploadIngest from "./pages/UploadIngest";

export default function App() {
  useEffect(() => {
    ensureLogin().catch(() => {});
  }, []);

  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="*"
            element={
              <div className="min-h-screen bg-rawPutty text-peatCharcoal">
                <Header />
                <Sidebar />
                <div className="pl-64">
                  <main className="w-full min-h-screen pt-24 pb-16 px-6">
                    <div className="flex flex-col w-full max-w-[1540px] mx-auto gap-5">
                      <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/devices" element={<Devices />} />
                        <Route path="/devices/:deviceId" element={<DeviceDetail />} />
                        <Route path="/training" element={<TrainingLoop />} />
                        <Route path="/upload" element={<UploadIngest />} />
                        <Route path="/reports" element={<ReportPreview />} />
                      </Routes>
                    </div>
                  </main>
                </div>
                <Footer />
              </div>
            }
          />
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}
