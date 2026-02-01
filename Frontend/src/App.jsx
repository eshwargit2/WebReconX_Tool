"use client"

import { useState, useEffect } from "react"
import Header from "./components/Header"
import SearchSection from "./components/SearchSection"
import Dashboard from "./components/Dashboard"
import LoadingSection from "./components/LoadingSection"
import XSSVulnerability from "./components/XSSVulnerability"
import SQLInjection from "./components/SQLInjection"
import SQLInjectionTester from "./components/SQLInjectionTester"
import ScanOptionsModal from "./components/ScanOptionsModal"
import WhoisInfo from "./components/WhoisInfo"
import DirectoryScan from "./components/DirectoryScan"
import Documentation from "./components/Documentation"
import About from "./components/About"
import SecurityHeaders from "./components/SecurityHeaders"
import ReportDownload from "./components/ReportDownload"

import { analyzeWebsite, scanXSSVulnerability, scanSQLInjection } from "./services/api"

function App() {
  const [analyzed, setAnalyzed] = useState(false)
  const [loading, setLoading] = useState(false)
  const [currentOperation, setCurrentOperation] = useState('')
  const [scanProgress, setScanProgress] = useState(0)
  const [analysisData, setAnalysisData] = useState(null)
  const [error, setError] = useState(null)
  const [showModal, setShowModal] = useState(false)
  const [pendingUrl, setPendingUrl] = useState('')
  const [selectedTests, setSelectedTests] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [currentPage, setCurrentPage] = useState('home')

  // Handle hash changes for navigation
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.slice(1)
      if (hash === 'documentation') {
        setCurrentPage('documentation')
      } else if (hash === 'about') {
        setCurrentPage('about')
      } else {
        setCurrentPage('home')
      }
    }

    handleHashChange()
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])
  

  const handleAnalyze = async (url) => {
    setPendingUrl(url)
    setShowModal(true)
  }

  const handleConfirmScan = async (selectedTestsFromModal) => {
    setShowModal(false)
    setLoading(true)
    setError(null)
    setAnalyzed(false)
    setScanProgress(0)
    setSelectedTests(selectedTestsFromModal)
    
    const url = pendingUrl
    
    try {
      // Calculate total steps based on selected tests
      const steps = [
        { name: 'Resolving hostname', duration: 500, condition: true },
        { name: 'Performing Domain lookup', duration: 800, condition: selectedTestsFromModal.whois },
        { name: 'Scanning open ports', duration: 1500, condition: selectedTestsFromModal.ports },
        { name: 'Detecting WAF protection', duration: 800, condition: selectedTestsFromModal.waf },
        { name: 'Detecting technologies', duration: 800, condition: selectedTestsFromModal.tech },
        { name: 'Testing XSS vulnerabilities', duration: 1000, condition: selectedTestsFromModal.xss },
        { name: 'Testing SQL injection', duration: 1000, condition: selectedTestsFromModal.sqli },
        { name: 'Generating AI security report', duration: 2000, condition: selectedTestsFromModal.ai_analysis !== false },
      ].filter(step => step.condition);

      const totalSteps = steps.length;
      let currentStep = 0;

      // Update progress for each step
      for (const step of steps) {
        setCurrentOperation(step.name)
        setScanProgress(Math.round((currentStep / totalSteps) * 100))
        await new Promise(resolve => setTimeout(resolve, step.duration))
        currentStep++
      }
      
      setScanProgress(95) // Show near completion before final API response
      
      // Pass selected tests to backend - AI analysis happens after all scans (including SQLi)
      const data = await analyzeWebsite(url, selectedTestsFromModal)
      
      setScanProgress(100)
      setAnalysisData(data)
      setAnalyzed(true)
    } catch (err) {
      setError(err.message || 'Failed to analyze website. Please check if the backend server is running.')
      console.error('Analysis error:', err)
    } finally {
      setLoading(false)
      setCurrentOperation('')
      setScanProgress(0)
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
        progress={scanProgress}
        onClose={() => setShowModal(false)}
        onConfirm={handleConfirmScan}
        url={pendingUrl}
      />
      <Header onSidebarToggle={setSidebarOpen} />
      
      {/* Conditional rendering based on current page */}
      {currentPage === 'documentation' ? (
        <main className={`transition-all duration-300 ${sidebarOpen ? 'lg:ml-64' : 'lg:ml-0'}`}>
          <Documentation />
        </main>
      ) : currentPage === 'about' ? (
        <main className={`transition-all duration-300 ${sidebarOpen ? 'lg:ml-64' : 'lg:ml-0'}`}>
          <About />
        </main>
      ) : (
        /* Main content with sidebar offset */
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
            
            {/* Security Configuration Section */}
            {selectedTests?.security_headers && analysisData.security_headers && (
              <div id="security-config" className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8 scroll-mt-20">
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                  <span className="text-green-400">🛡️</span>
                  Security Configuration
                </h2>
                <SecurityHeaders headersData={analysisData.security_headers} />
              </div>
            )}
            
            {/* Reconnaissance & Information Gathering Section */}
            {selectedTests?.directory && analysisData.directory_scan && (
              <div id="endpoint-discovery" className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8 scroll-mt-20">
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                  <span className="text-blue-400">🔍</span>
                  Reconnaissance & Endpoint Discovery
                </h2>
                <DirectoryScan directoryData={analysisData.directory_scan} />
              </div>
            )}
            
            {/* Vulnerabilities Section */}
            {((selectedTests?.xss && analysisData.xss_scan) || (selectedTests?.sqli && analysisData.sqli_scan)) && (
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
              </div>
            )}
            
            {/* Report Download Section */}
            <div id="report-download" className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 mb-8">
              <h2 className="text-2xl font-bold text-white mb-4 text-center flex items-center justify-center gap-2">
                <span className="text-purple-400">📥</span>
                Export Report
              </h2>
              <ReportDownload analysisData={analysisData} selectedTests={selectedTests} />
            </div>
          </>
        )}
        </div>
      </main>
      )}
    </div>
  )
}

export default App
