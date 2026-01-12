"use client"

import { useState } from "react"
import { Search, Bug } from "lucide-react"

export default function SearchSection({ onAnalyze, loading }) {
  const [url, setUrl] = useState("")

  const handleAnalyze = () => {
    if (url.trim()) {
      onAnalyze(url)
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleAnalyze()
    }
  }

  return (
    <div className="mb-12">
      <div className="flex gap-3 max-w-3xl">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Enter website URL (e.g. example.com)"
          className="flex-1 rounded-lg bg-white px-4 py-3 text-slate-900 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          disabled={loading}
        />
        <button
          onClick={handleAnalyze}
          disabled={loading || !url.trim()}
          className="rounded-lg bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 px-8 py-3 font-semibold text-white transition flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
        >
          <Search size={18} />
          {loading ? 'Analyzing...' : 'Analyze Security'}
        </button>
      </div>
      <p className="mt-3 text-sm text-slate-400">Comprehensive security scan including ports, WAF, technologies, and XSS vulnerabilities</p>
    </div>
  )
}
