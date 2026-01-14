import { Shield, User, Key, X, Check } from "lucide-react"
import { useState } from "react"

export default function Header() {
  const [showApiKeyModal, setShowApiKeyModal] = useState(false)
  const [apiKey, setApiKey] = useState(localStorage.getItem('gemini_api_key') || '')
  const [saved, setSaved] = useState(false)

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

  return (
    <>
      <header className="border-b border-slate-700/50 bg-slate-900/50 backdrop-blur-md">
        <div className="container mx-auto flex items-center justify-between px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 p-2">
              <Shield size={24} className="text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">WebReconX</h1>
          </div>

          <nav className="hidden gap-8 md:flex">
            <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
              Home
            </a>
            <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
              Features
            </a>
            <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
              Report History
            </a>
          </nav>

          <div className="flex items-center gap-4">
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
            <button className="rounded-full p-2 hover:bg-slate-800 transition">
              <User size={20} className="text-slate-400" />
            </button>
          </div>
        </div>
      </header>

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
