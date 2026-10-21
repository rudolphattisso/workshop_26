/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      keyframes: {
        popin: { "0%": { opacity: "0", transform: "translateX(1rem)" }, "100%": { opacity: "1", transform: "none" } },
      },
      animation: { popin: "popin .25s ease-out" },
    },
  },
  plugins: [],
};
