import { Loader2, Shield, Search, Globe, Lock, Bug } from "lucide-react"

export default function LoadingSection({ isLoading, currentOperation = "Initializing scan..." }) {
  if (!isLoading) return null

  const scanSteps = [
    { icon: Globe, label: "Resolving hostname...", id: 'hostname' },
    { icon: Search, label: "Scanning open ports...", id: 'ports' },
    { icon: Shield, label: "Detecting WAF protection...", id: 'waf' },
    { icon: Lock, label: "Detecting technologies...", id: 'tech' },
    { icon: Bug, label: "Testing for XSS vulnerabilities...", id: 'xss' },
  ]

  return (
    <div className="fixed inset-0 bg-slate-950/90 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="max-w-md w-full mx-4">
        <div className="rounded-lg bg-slate-800/90 border border-slate-700/50 p-8 backdrop-blur">
          {/* Animated Logo/Icon */}
          <div className="flex justify-center mb-8">
            <div className="relative">
              <Loader2 size={64} className="text-cyan-400 animate-spin" />
              <div className="absolute inset-0 flex items-center justify-center">
                <Shield size={32} className="text-cyan-300 animate-pulse" />
              </div>
            </div>
          </div>

          {/* Title */}
          <h2 className="text-2xl font-bold text-white text-center mb-2">
            Analyzing Website Security
          </h2>
          <p className="text-slate-400 text-center text-sm mb-8">
            {currentOperation}
          </p>

          {/* Progress Steps */}
          <div className="space-y-4 mb-6">
            {scanSteps.map((step, idx) => {
              const IconComponent = step.icon
              const isActive = currentOperation.toLowerCase().includes(step.label.toLowerCase().split('...')[0])
              return (
                <div
                  key={idx}
                  className={`flex items-center gap-3 p-3 rounded-lg transition-all ${
                    isActive ? 'bg-cyan-500/20 border border-cyan-500/50' : 'bg-slate-700/30'
                  }`}
                >
                  <div className={`p-2 rounded-full ${
                    isActive ? 'bg-cyan-500/30' : 'bg-slate-700/50'
                  }`}>
                    <IconComponent size={20} className={isActive ? 'text-cyan-300' : 'text-slate-400'} />
                  </div>
                  <span className={`text-sm ${
                    isActive ? 'text-white font-semibold' : 'text-slate-400'
                  }`}>{step.label}</span>
                  {isActive && (
                    <div className="ml-auto">
                      <Loader2 size={16} className="text-cyan-400 animate-spin" />
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs text-slate-400">
              <span>Scanning in progress...</span>
              <span className="animate-pulse">●</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-500 rounded-full animate-loading-bar"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
