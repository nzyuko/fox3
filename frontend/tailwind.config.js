/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'brand-primary': '#4f46e5', // modern indigo
                'brand-secondary': '#818cf8',
                'dark-bg': '#0f172a',    // sleek dark slate
                'dark-panel': '#1e293b',
            }
        },
    },
    plugins: [],
}
