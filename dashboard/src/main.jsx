import React from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/barlow/latin-400.css'
import '@fontsource/barlow/latin-500.css'
import '@fontsource/barlow/latin-600.css'
import '@fontsource/martian-mono/latin-400.css'
import '@fontsource/martian-mono/latin-500.css'
import './styles.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(<App />)
