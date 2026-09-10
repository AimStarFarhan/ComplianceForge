import { createContext, useContext, useEffect, useState } from "react";

const ThemeCtx = createContext({ dark: false, toggle: () => {} });

export function ThemeProvider({ children }) {
  const [dark, setDark] = useState(() => {
    try {
      return window.localStorage.getItem("cf-theme") === "dark";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (dark) root.classList.add("dark");
    else root.classList.remove("dark");
    try {
      window.localStorage.setItem("cf-theme", dark ? "dark" : "light");
    } catch {}
  }, [dark]);

  const toggle = () => setDark((d) => !d);
  return <ThemeCtx.Provider value={{ dark, toggle }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);

/** Sun/moon pill toggle — used in landing nav + console header. */
export function ThemeToggle({ compact = false }) {
  const { dark, toggle } = useTheme();
  return (
    <button
      onClick={toggle}
      title={dark ? "Switch to light mode" : "Switch to dark mode"}
      aria-label="Toggle dark mode"
      className="relative flex items-center h-8 rounded-full border border-camoSeam bg-olivePanel px-1 transition-colors hover:border-softSage/40"
      style={{ width: compact ? 64 : 64 }}
    >
      <span
        className="absolute top-1 left-1 w-6 h-6 rounded-full flex items-center justify-center transition-all duration-300"
        style={{
          transform: dark ? "translateX(28px)" : "translateX(0)",
          background: "var(--accent)",
        }}
      >
        <span
          className="material-symbols-outlined text-[15px]"
          style={{ color: "var(--card)" }}
        >
          {dark ? "dark_mode" : "light_mode"}
        </span>
      </span>
      <span className="w-6 h-6 rounded-full flex items-center justify-center ml-7 opacity-0 pointer-events-none" />
    </button>
  );
}
