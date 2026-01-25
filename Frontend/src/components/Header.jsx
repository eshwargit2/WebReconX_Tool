import { Shield, User, Key, X, Check, Menu, Home, FileText, Settings, Info, BookOpen, Globe, Layers, TrendingUp, Lightbulb, Bug, ChevronRight } from "lucide-react"
import { useState } from "react"

export default function Header({ onSidebarToggle }) {
  const [showApiKeyModal, setShowApiKeyModal] = useState(false)
  const [apiKey, setApiKey] = useState(localStorage.getItem('gemini_api_key') || '')
  const [saved, setSaved] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const handleSidebarToggle = () => {
    const newState = !sidebarOpen
    setSidebarOpen(newState)
    if (onSidebarToggle) {
      onSidebarToggle(newState)
    }
  }

  const handleSaveApiKey = () => {
    localStorage.setItem('gemini_api_key', apiKey)
    setSaved(true)
    setTimeout(() => {
      setSaved(false)
      setShowApiKeyModal(false)
    }, 1500)
  }

  const handleRemoveApiKey = () => {
    localStorage.removeItem('gemini_api_key')
    setApiKey('')
    setSaved(false)
  }

  const menuItems = [
    { icon: Home, label: 'Home', href: '#', badge: null },
    { icon: FileText, label: 'Report History', href: '#history', badge: null },
    { icon: BookOpen, label: 'Documentation', href: '#docs', badge: null },
    { icon: Info, label: 'About', href: '#about', badge: null }
  ]

  const scanMenuItems = [
    { icon: Globe, label: 'Domain Information', href: '#domain-info' },
    { icon: Globe, label: 'Website Overview', href: '#website-overview' },
    { icon: Layers, label: 'Technology Stack', href: '#tech-stack' },
    { icon: TrendingUp, label: 'Risk Assessment', href: '#risk-assessment' },
    { icon: Lightbulb, label: 'Recommendations', href: '#recommendations' },
    { icon: Bug, label: 'Vulnerabilities', href: '#vulnerabilities' }
  ]

  const scrollToSection = (href) => {
    const element = document.querySelector(href)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
    setMobileMenuOpen(false)
  }

  return (
    <>
      {/* Top Header - Minimal */}
      <header className="border-b border-slate-700/50 bg-slate-900/50 backdrop-blur-md sticky top-0 z-40">
        <div className="flex items-center justify-between px-4 py-4">
          {/* Logo Section */}
          <div className="flex items-center gap-3">
            <button 
              onClick={handleSidebarToggle}
              className="p-2 rounded-lg hover:bg-slate-800 transition"
              title="Toggle Menu"
            >
              <Menu size={20} className="text-slate-400" />
            </button>
            <div className="rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 p-2">
              <Shield size={24} className="text-white" />
            </div>
            <h1 className="text-xl lg:text-2xl font-bold text-white">WebReconX</h1>
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-2">
            {/* AI API Key Button */}
            <button 
              onClick={() => setShowApiKeyModal(true)}
              className={`flex items-center gap-2 rounded-lg px-3 py-2 transition ${
                apiKey ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
              }`}
              title="Gemini API Key"
            >
              <Key size={16} />
              <span className="text-xs font-medium hidden sm:inline">
                {apiKey ? 'AI Enabled' : 'Setup AI'}
              </span>
            </button>

            {/* User Profile Button */}
            <button className="hidden md:flex rounded-full p-2 hover:bg-slate-800 transition">
              <User size={20} className="text-slate-400" />
            </button>
          </div>
        </div>
      </header>

      {/* Sidebar Navigation */}
      <aside className={`fixed left-0 top-[73px] h-[calc(100vh-73px)] bg-slate-900/95 backdrop-blur-md border-r border-slate-700/50 transition-transform duration-300 z-30 w-64 ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      }`}>
        <nav className="flex flex-col h-full p-4 overflow-y-auto">
          {/* Main Menu */}
          <div className="space-y-2 mb-6">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 px-3">Main Menu</p>
            <a href="/" className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition group">
              <Home size={20} className="group-hover:scale-110 transition-transform" />
              <span className="font-medium">Home</span>
            </a>
            
            <a href="#history" className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition group">
              <FileText size={20} className="group-hover:scale-110 transition-transform" />
              <span className="font-medium">Report History</span>
            </a>
           
          </div>

          {/* Scan Sections */}
          <div className="space-y-2 mb-6">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 px-3">Scan Sections</p>
            {scanMenuItems.map((item) => (
              <button
                key={item.label}
                onClick={() => scrollToSection(item.href)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition group text-left"
              >
                <item.icon size={20} className="group-hover:scale-110 transition-transform" />
                <span className="font-medium">{item.label}</span>
                <ChevronRight size={16} className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
              </button>
            ))}
          </div>

          {/* Bottom Menu */}
          <div className="mt-auto space-y-2 pt-6 border-t border-slate-700/50">
            <a href="#documentation" onClick={(e) => { e.preventDefault(); window.location.hash = 'documentation'; }} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition group">
              <BookOpen size={20} className="group-hover:scale-110 transition-transform" />
              <span className="font-medium">Documentation</span>
            </a>
            <a href="#about" onClick={(e) => { e.preventDefault(); window.location.hash = 'about'; }} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition group">
              <Info size={20} className="group-hover:scale-110 transition-transform" />
              <span className="font-medium">About</span>
            </a>
          </div>
        </nav>
      </aside>

      {/* Overlay for mobile */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/60 z-20 lg:hidden top-[73px]"
          onClick={() => setSidebarOpen(false)}
        ></div>
      )}

      {/* API Key Modal */}
      {showApiKeyModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-2xl max-w-md w-full">
            <div className="border-b border-slate-700 p-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-white">Gemini API Key</h2>
              </div>
              <button
                onClick={() => setShowApiKeyModal(false)}
                className="p-1 hover:bg-slate-700 rounded transition"
              >
                <X className="w-5 h-5 text-slate-400" />
              </button>
            </div>

            <div className="p-4 space-y-4">
              <p className="text-sm text-slate-400">
                Enter your Google Gemini API key to enable AI-powered security analysis and recommendations.
              </p>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  API Key
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="AIzaSy..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                <p className="text-xs text-blue-300">
                  Get your API key from{' '}
                  <a 
                    href="https://makersuite.google.com/app/apikey" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:underline"
                  >
                    Google AI Studio
                  </a>
                </p>
              </div>

              <div className="flex gap-2">
                {apiKey && (
                  <button
                    onClick={handleRemoveApiKey}
                    className="flex-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 px-4 py-2 rounded-lg font-semibold transition"
                  >
                    Remove
                  </button>
                )}
                <button
                  onClick={handleSaveApiKey}
                  disabled={!apiKey || saved}
                  className="flex-1 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg font-semibold transition flex items-center justify-center gap-2"
                >
                  {saved ? (
                    <>
                      <Check className="w-4 h-4" />
                      Saved
                    </>
                  ) : (
                    'Save'
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
