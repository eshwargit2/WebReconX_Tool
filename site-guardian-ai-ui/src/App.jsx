"use client"

import { useState } from "react"
import Header from "./components/Header"
import SearchSection from "./components/SearchSection"
import Dashboard from "./components/Dashboard"
import LoadingSection from "./components/LoadingSection"
import XSSVulnerability from "./components/XSSVulnerability"
import { analyzeWebsite, scanXSSVulnerability } from "./services/api"

function App() {
  const [analyzed, setAnalyzed] = useState(false)
  const [loading, setLoading] = useState(false)
  const [currentOperation, setCurrentOperation] = useState('')
  const [analysisData, setAnalysisData] = useState(null)
  const [error, setError] = useState(null)

  const handleAnalyze = async (url) => {
    setLoading(true)
    setError(null)
    setAnalyzed(false)
    
    try {
      setCurrentOperation('Resolving hostname...')
      await new Promise(resolve => setTimeout(resolve, 300))
      
      setCurrentOperation('Scanning open ports...')
      await new Promise(resolve => setTimeout(resolve, 300))
      
      setCurrentOperation('Detecting WAF protection...')
      await new Promise(resolve => setTimeout(resolve, 300))
      
      setCurrentOperation('Detecting technologies...')
      await new Promise(resolve => setTimeout(resolve, 300))
      
      setCurrentOperation('Testing for XSS vulnerabilities...')
      
      const data = await analyzeWebsite(url)
      setAnalysisData(data)
      setAnalyzed(true)
    } catch (err) {
      setError(err.message || 'Failed to analyze website. Please check if the backend server is running.')
      console.error('Analysis error:', err)
    } finally {
      setLoading(false)
      setCurrentOperation('')
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <LoadingSection isLoading={loading} currentOperation={currentOperation} />
      <Header />
      <main className="container mx-auto px-4 py-8">
        <SearchSection 
          onAnalyze={handleAnalyze} 
          loading={loading}
        />
        
        {error && (
          <div className="mb-8 p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400">
            <p className="font-semibold">Error:</p>
            <p>{error}</p>
          </div>
        )}
        
        {analyzed && !loading && analysisData && (
          <>
            <Dashboard data={analysisData} />
            {analysisData.xss_scan && (
              <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8">
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                  <span className="text-cyan-400">⚡</span>
                  Basic Attack Check
                </h2>
                <XSSVulnerability xssData={analysisData.xss_scan} />
              </div>
            )}
          </>
        )}
      </main>
    </div>
  )
}

export default App
