/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // Tactical Field Telemetry — sidebar/header/footer chrome
        tacticalOlive: "#343E33",
        camoSeam: "#434F42",
        softSage: "#D2DCD0",
        sageMuted: "#9EABA0",
        olivePanel: "#2B342A",
        oliveHover: "#3D493C",
        oliveDeep: "#273026",
        oliveInk: "#1F261E",
        // Main canvas — Muted Raw Putty
        rawPutty: "#EBE7DF",
        warmSandstone: "#F7F5EE",
        sandstoneLight: "#FDFCF8",
        weatheredTaupe: "#D6D0C4",
        taupeMuted: "#726F67",
        peatCharcoal: "#1C201A",
        sprucePine: "#1E3527",
        sprucePineHover: "#294534",
        terracottaRust: "#B84A39",
        rustWash: "#FBECEB",
        ochreHazard: "#C27803",
        ochreWash: "#FDF5E6",
        mutedMeadow: "#2D6A4F",
        meadowWash: "#E8F2EC",
        creamParchment: "#F0ECE1",
        parchmentDeep: "#E7E2D5",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Consolas", "monospace"],
        display: ["Space Grotesk", "system-ui", "sans-serif"],
      },
      boxShadow: {
        sm: "0 1px 2px 0 rgba(28, 32, 26, 0.08)",
        md: "0 2px 6px -1px rgba(28, 32, 26, 0.10)",
      },
    },
  },
  plugins: [],
};
