import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Corporate color palette
        'brand': {
          'green': '#86BC25',
          'green-dark': '#6B9B1E',
          'green-light': '#A3D44E',
          'blue': '#0076A8',
          'blue-dark': '#005A82',
          'blue-light': '#0096D6',
          'navy': '#012169',
          'navy-dark': '#001140',
          'navy-light': '#1A3A7A',
          'teal': '#00A3E0',
          'black': '#000000',
          'white': '#FFFFFF',
          'gray': {
            50: '#F8F9FA',
            100: '#F2F2F2',
            200: '#E6E6E6',
            300: '#CCCCCC',
            400: '#999999',
            500: '#666666',
            600: '#4D4D4D',
            700: '#333333',
            800: '#1A1A1A',
            900: '#0D0D0D',
          },
        },
        // Severity colors
        'severity': {
          'critical': '#DC2626',
          'high': '#EA580C',
          'medium': '#D97706',
          'low': '#2563EB',
          'informational': '#6B7280',
        },
        // Status colors
        'status': {
          'pass': '#86BC25',
          'fail': '#DC2626',
          'running': '#0076A8',
          'pending': '#D97706',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
}

export default config
