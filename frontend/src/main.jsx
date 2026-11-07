import React from 'react'
import ReactDOM from 'react-dom/client'
import '@fontsource-variable/inter-tight'
import '@fontsource-variable/jetbrains-mono'
import App from './App.jsx'
import { ThemeProvider } from './theme'
import { FeedbackProvider } from './feedback'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider>
      <FeedbackProvider>
        <App />
      </FeedbackProvider>
    </ThemeProvider>
  </React.StrictMode>,
)
