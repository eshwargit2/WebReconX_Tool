"use client"

import { useState } from "react"
import Header from "./components/Header"
import SearchSection from "./components/SearchSection"
import Dashboard from "./components/Dashboard"
import LoadingSection from "./components/LoadingSection"
import XSSVulnerability from "./components/XSSVulnerability"
import SQLInjection from "./components/SQLInjection"
import CSRFDetection from "./components/CSRFDetection"
import SQLInjectionTester from "./components/SQLInjectionTester"
import ScanOptionsModal from "./components/ScanOptionsModal"
import WhoisInfo from "./components/WhoisInfo"

import { analyzeWebsite, scanXSSVulnerability, scanSQLInjection } from "./services/api"

function App() {
  const [analyzed, setAnalyzed] = useState(false)
  const [loading, setLoading] = useState(false)
  const [currentOperation, setCurrentOperation] = useState('')
  const [analysisData, setAnalysisData] = useState(null)
  const [error, setError] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const [pendingUrl, setPendingUrl] = useState('')
  const [selectedTests, setSelectedTests] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  

  const handleAnalyze = async (url) => {
    setPendingUrl(url)
    setShowModal(true)
  }

  const handleConfirmScan = async (selectedTestsFromModal) => {
    setShowModal(false)
    setLoading(true)
    setError(null)
    setAnalyzed(false)
    setSelectedTests(selectedTestsFromModal)
    
    const url = pendingUrl
    
    try {
      setCurrentOperation('Resolving hostname')
      await new Promise(resolve => setTimeout(resolve, 300))
      
      if (selectedTestsFromModal.whois) {
        setCurrentOperation('Performing WHOIS lookup')
        await new Promise(resolve => setTimeout(resolve, 300))
      }
      
      if (selectedTestsFromModal.ports) {
        setCurrentOperation('Scanning open ports')
        await new Promise(resolve => setTimeout(resolve, 300))
      }
      
      if (selectedTestsFromModal.waf) {
        setCurrentOperation('Detecting WAF protection')
        await new Promise(resolve => setTimeout(resolve, 300))
      }
      
      if (selectedTestsFromModal.tech) {
        setCurrentOperation('Detecting technologies')
        await new Promise(resolve => setTimeout(resolve, 300))
      }
      
      // Show AI analysis operation before backend call
      if (selectedTestsFromModal.ai_analysis !== false) {
        setCurrentOperation('Generating AI security analysis')
      }
      
      // Pass selected tests to backend - AI analysis happens after all scans
      const data = await analyzeWebsite(url, selectedTestsFromModal)
      
      // Run XSS scan if selected (already handled by backend)
      if (selectedTestsFromModal.xss) {
        setCurrentOperation('Testing XSS vulnerabilities')
      }
      
      // Run SQL injection scan if selected
      if (selectedTestsFromModal.sqli) {
        setCurrentOperation('Testing SQL injection')
        try {
          const sqliData = await scanSQLInjection(url)
          data.sqli_scan = sqliData.sqli_scan
        } catch (sqliErr) {
          console.error('SQL injection scan error:', sqliErr)
        }
      }
      
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
      <LoadingSection 
        isLoading={loading} 
        currentOperation={currentOperation}
        selectedTests={selectedTests}
      />
      <ScanOptionsModal 
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        onConfirm={handleConfirmScan}
        url={pendingUrl}
      />
      <Header onSidebarToggle={setSidebarOpen} />
      {/* Main content with sidebar offset */}
      <main className={`transition-all duration-300 px-4 py-8 ${sidebarOpen ? 'lg:ml-64' : 'lg:ml-0'}`}>
        <div className="container mx-auto">
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
            {/* Domain Information Section */}
            {selectedTests?.whois && analysisData.whois && analysisData.whois.success && (
              <div id="domain-info" className="scroll-mt-20">
                <WhoisInfo whoisData={analysisData.whois} />
              </div>
            )}
            
            {/* Website Overview & Technology Stack Section */}
            <div id="website-overview" className="scroll-mt-20">
              <Dashboard data={analysisData} selectedTests={selectedTests} />
            </div>
            
            {/* Vulnerabilities Section */}
            {((selectedTests?.xss && analysisData.xss_scan) || (selectedTests?.sqli && analysisData.sqli_scan) || (selectedTests?.csrf && analysisData.csrf_scan)) && (
              <div id="vulnerabilities" className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8 scroll-mt-20">
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                  <span className="text-cyan-400">⚡</span>
                  Vulnerability Assessment
                </h2>
                {selectedTests?.xss && analysisData.xss_scan && (
                  <XSSVulnerability xssData={analysisData.xss_scan} />
                )}
                {selectedTests?.sqli && analysisData.sqli_scan && (
                  <SQLInjection sqliData={analysisData.sqli_scan} />
                )}
                {selectedTests?.csrf && analysisData.csrf_scan && (
                  <CSRFDetection csrfData={analysisData.csrf_scan} />
                )}
              </div>
            )}
          </>
        )}
        </div>
      </main>
    </div>
  )
}

export default App
