import { createContext, useCallback, useContext, useState } from "react";

const ToastCtx = createContext(() => {});

export function ToastProvider({ children }) {
  const [toast, setToast] = useState(null);

  const showToast = useCallback((message) => {
    setToast({ message, id: Date.now() });
    setTimeout(() => setToast(null), 2800);
  }, []);

  return (
    <ToastCtx.Provider value={showToast}>
      {children}
      <div
        className={`fixed bottom-14 right-6 pointer-events-none transition-all duration-300 z-[60] flex items-center gap-2.5 bg-tacticalOlive border border-camoSeam text-softSage px-4 py-2.5 rounded-md shadow-2xl ${
          toast ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0"
        }`}
      >
        <span className="material-symbols-outlined text-mutedMeadow text-[20px]">check_circle</span>
        <span className="font-mono text-xs font-semibold">{toast?.message || ""}</span>
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

export async function copyText(text, toast, msg = "Copied to clipboard") {
  try {
    await navigator.clipboard.writeText(text);
    toast(msg);
    return true;
  } catch {
    toast("Copy failed — clipboard unavailable");
    return false;
  }
}
