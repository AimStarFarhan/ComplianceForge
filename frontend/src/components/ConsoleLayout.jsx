import Header from "./Header";
import Sidebar from "./Sidebar";
import Footer from "./Footer";
import ChatBot from "./ChatBot";
import { Outlet } from "react-router-dom";

/** The embedded ComplianceForge console — mounted under /console/* behind the landing page. */
export default function ConsoleLayout() {
  return (
    <div className="min-h-screen bg-rawPutty text-peatCharcoal">
      <Header />
      <Sidebar />
      <div className="pl-64">
        <main className="w-full min-h-screen pt-24 pb-16 px-6">
          <div className="flex flex-col w-full max-w-[1540px] mx-auto gap-5">
            <Outlet />
          </div>
        </main>
      </div>
      <Footer />
      <ChatBot />
    </div>
  );
}
