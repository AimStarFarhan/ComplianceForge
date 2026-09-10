  /** @type {import('tailwindcss').Config} */
  export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        monochrome: {
          app: "#FFFFFF",
          card: "#FAFAFA",
          code: "#F4F4F5",
          border: "#E4E4E7",
          main: "#09090B",
          muted: "#71717A",
        },
        // Warm Editorial & Terracotta — LIGHT (cream paper, terracotta signal)
        // cf* tokens are CSS-var driven so the whole landing themes in dark mode
        cfink: "var(--paper)",
        cfink2: "var(--pane)",
        cfsurface: "var(--card)",
        cfline: "var(--line)",
        cftext: "var(--ink)",
        cfmuted: "var(--ink-soft)",
        cfdim: "var(--ink-faint)",
        cfsignal: "var(--accent)",
        cfsignalDeep: "var(--accent-hover)",
        cfsignal2: "var(--warn)",
        cffail: "var(--fail)",
        cfwarn: "var(--warn)",
        cfpass: "var(--pass)",
        // Warm Editorial & Terracotta — console chrome + canvas (CSS-var driven for dark mode)
        tacticalOlive: "var(--chrome)",
        camoSeam: "var(--chrome2)",
        softSage: "var(--chrome-text)",
        sageMuted: "var(--chrome-muted)",
        olivePanel: "var(--chrome-panel)",
        oliveHover: "var(--chrome-hover)",
        oliveDeep: "var(--chrome-deep)",
        oliveInk: "var(--chrome-deep)",
        rawPutty: "var(--paper)",
        warmSandstone: "var(--card)",
        sandstoneLight: "var(--card2)",
        weatheredTaupe: "var(--line)",
        taupeMuted: "var(--ink-soft)",
        peatCharcoal: "var(--ink)",
        sprucePine: "var(--accent)",
        sprucePineHover: "var(--accent-hover)",
        terracottaRust: "var(--fail)",
        rustWash: "var(--fail-wash)",
        ochreHazard: "var(--warn)",
        ochreWash: "var(--warn-wash)",
        mutedMeadow: "var(--pass)",
        meadowWash: "var(--pass-wash)",
        creamParchment: "var(--pane)",
        parchmentDeep: "var(--pane-deep)",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "system-ui", "sans-serif"],
        mono: ['"SF Mono"', '"Geist Mono"', '"JetBrains Mono"', "ui-monospace", "Consolas", "monospace"],
        display: ["Fraunces", "Georgia", '"Times New Roman"', "serif"],
      },
      boxShadow: {
        sm: "0 1px 2px 0 rgba(28, 32, 26, 0.08)",
        md: "0 2px 6px -1px rgba(28, 32, 26, 0.10)",
      },
      keyframes: {
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(420%)" },
        },
        pulseSoft: {
          "0%, 100%": { opacity: "0.5" },
          "50%": { opacity: "1" },
        },
        flowDown: {
          "0%": { transform: "translateY(-8px)", opacity: "0" },
          "15%": { opacity: "1" },
          "100%": { transform: "translateY(120px)", opacity: "0" },
        },
        fadeUp: {
          "0%": { transform: "translateY(14px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        shimmer: {
          "0%": { "background-position": "0% 50%" },
          "100%": { "background-position": "200% 50%" },
        },
        floaty: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-12px)" },
        },
        marquee: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-50%)" },
        },
      },
      animation: {
        scanline: "scanline 2.8s ease-in-out infinite",
        pulseSoft: "pulseSoft 2.4s ease-in-out infinite",
        flowDown: "flowDown 2.2s linear infinite",
        fadeUp: "fadeUp 0.7s ease-out both",
        shimmer: "shimmer 4.5s linear infinite",
        floaty: "floaty 7s ease-in-out infinite",
        marquee: "marquee 18s linear infinite",
      },
    },
  },
  plugins: [],
};
