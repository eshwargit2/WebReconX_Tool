import { Globe, Server, Code, Database, Zap, Lock, Shield, Network } from "lucide-react"
import { useState } from "react"

export default function WebsiteOverview({ data, selectedTests }) {
  const [copiedIndex, setCopiedIndex] = useState(null)

  const handleCopy = (value, index) => {
    navigator.clipboard.writeText(value)
    setCopiedIndex(index)
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  if (!data) {
    return (
      <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-6 backdrop-blur">
        <h2 className="text-xl font-bold text-white mb-6">Website Overview</h2>
        <p className="text-slate-400 text-sm">Enter a URL to analyze...</p>
      </div>
    )
  }

  const showPorts = selectedTests?.ports !== false;
  const showWAF = selectedTests?.waf !== false;

  const overviewItems = [
    { icon: Globe, label: "Website URL", value: data.url || "N/A", show: true },
    { icon: Server, label: "IP Address", value: data.ip_address || "N/A", show: true },
    { icon: Network, label: "Hostname", value: data.hostname || data.url || "N/A", show: true },
    { icon: Shield, label: "Open Ports", value: data.total_open_ports?.toString() || "0", show: showPorts },
    { icon: Lock, label: "WAF Protection", value: data.waf?.name || "None detected", show: showWAF },
    { icon: Zap, label: "Scan Date", value: data.scan_date || "N/A", show: true },
  ].filter(item => item.show !== false)

  return (
    <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-6 backdrop-blur">
      <h2 className="text-xl font-bold text-white mb-6">Website Overview</h2>
      <div className="space-y-4">
        {overviewItems.map((item, idx) => {
          const IconComponent = item.icon
          return (
            <div
              key={idx}
              className="flex items-center justify-between p-3 rounded-lg bg-slate-700/30 hover:bg-slate-700/50 transition"
            >
              <div className="flex items-center gap-3 flex-1">
                <IconComponent size={20} className="text-cyan-400" />
                <div className="flex-1">
                  <p className="text-xs text-slate-400">{item.label}</p>
                  <p className="text-sm font-medium text-white break-all">{item.value}</p>
                </div>
              </div>
              <button 
                onClick={() => handleCopy(item.value, idx)}
                className="p-1 hover:bg-slate-600 rounded transition ml-2"
                title="Copy to clipboard"
              >
                {copiedIndex === idx ? (
                  <Check size={16} className="text-green-400" />
                ) : (
                  <Copy size={16} className="text-slate-400 hover:text-cyan-400" />
                )}
              </button>
            </div>
          )
        })}
      </div>

      {/* WAF Information */}
      {showWAF && data.waf && (
        <div className="mt-6 pt-6 border-t border-slate-700/50">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Shield size={20} className="text-cyan-400" />
            Web Application Firewall (WAF)
          </h3>
          <div className="p-4 rounded-lg bg-slate-700/30 border border-slate-600/30">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-sm">Status:</span>
                <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                  data.waf.detected 
                    ? 'bg-green-500/20 text-green-400' 
                    : 'bg-slate-600/20 text-slate-400'
                }`}>
                  {data.waf.detected ? 'Protected' : 'Not Detected'}
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-slate-400 text-sm">Firewall Name:</span>
                <span className="text-white font-semibold text-base">
                  {data.waf.full_name || data.waf.name}
                </span>
              </div>
              {data.waf.version && data.waf.version !== 'N/A' && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 text-sm">Version:</span>
                  <span className="text-cyan-300 text-sm font-mono bg-slate-800/50 px-2 py-1 rounded">
                    {data.waf.version}
                  </span>
                </div>
              )}
              {data.waf.confidence && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 text-sm">Confidence:</span>
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${
                    data.waf.confidence === 'High' ? 'bg-green-500/20 text-green-400' :
                    data.waf.confidence === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-slate-600/20 text-slate-400'
                  }`}>
                    {data.waf.confidence}
                  </span>
                </div>
              )}
              {data.waf.method && (
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 text-sm">Detection Method:</span>
                  <span className="text-slate-300 text-sm">{data.waf.method}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Open Ports Details */}
      {showPorts && data.open_ports && data.open_ports.length > 0 && (
        <div className="mt-6 pt-6 border-t border-slate-700/50">
          <h3 className="text-lg font-semibold text-white mb-4">Open Ports Details</h3>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {data.open_ports.map((portInfo, idx) => (
              <div
                key={idx}
                className="p-4 rounded-lg bg-slate-700/30 border border-slate-600/30 hover:bg-slate-700/50 transition"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <span className="text-cyan-400 font-mono font-bold text-lg">{portInfo.port}</span>
                    <span className="text-green-400 text-xs px-2 py-1 bg-green-500/10 rounded">{portInfo.state}</span>
                  </div>
                  <button 
                    onClick={() => handleCopy(`Port ${portInfo.port}: ${portInfo.service_name || portInfo.service}`, `port-${idx}`)}
                    className="p-1 hover:bg-slate-600 rounded transition"
                    title="Copy port info"
                  >
                    {copiedIndex === `port-${idx}` ? (
                      <Check size={14} className="text-green-400" />
                    ) : (
                      <Copy size={14} className="text-slate-400 hover:text-cyan-400" />
                    )}
                  </button>
                </div>
                <div className="space-y-1">
                  <div className="flex items-start gap-2">
                    <span className="text-slate-500 text-xs font-semibold min-w-[80px]">Service:</span>
                    <span className="text-slate-200 text-sm font-medium">{portInfo.service_name || portInfo.service}</span>
                  </div>
                  {portInfo.version && (
                    <div className="flex items-start gap-2">
                      <span className="text-slate-500 text-xs font-semibold min-w-[80px]">Version:</span>
                      <span className="text-slate-300 text-xs font-mono break-all">{portInfo.version}</span>
                    </div>
                  )}
                  {portInfo.product && (
                    <div className="flex items-start gap-2">
                      <span className="text-slate-500 text-xs font-semibold min-w-[80px]">Product:</span>
                      <span className="text-slate-300 text-xs">{portInfo.product}</span>
                    </div>
                  )}
                  {portInfo.ai_analysis && (
                    <div className="mt-2 p-2 bg-blue-500/10 border border-blue-500/30 rounded">
                      <p className="text-xs text-blue-300">
                        <span className="font-semibold">AI Analysis:</span> {portInfo.ai_analysis}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Copy() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path>
      <rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect>
    </svg>
  )
}

function Check({ size = 16, className = "" }) {
  return (
    <svg 
      width={size} 
      height={size} 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2"
      className={className}
    >
      <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
  )
}
