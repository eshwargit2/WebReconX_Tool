import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts"
import { AlertTriangle, Shield, TrendingUp } from "lucide-react"

export default function RiskAssessment({ data }) {
  const aiAnalysis = data?.ai_analysis
  const riskScore = aiAnalysis?.risk_score || data?.data?.risk_score || 0
  const riskLevel = aiAnalysis?.risk_level || "Unknown"
  const riskSummary = aiAnalysis?.risk_summary || ""
  const mostLikelyAttacks = aiAnalysis?.most_likely_attacks || []
  const openPortsCount = data?.total_open_ports || 0
  const isQuotaError = aiAnalysis?.error === 'quota_exceeded'
  
  // Calculate risk level based on score and AI analysis
  const getRiskLevel = () => {
    const level = riskLevel.toLowerCase()
    if (level === "critical" || riskScore >= 80) 
      return { label: "Critical Risk", color: "text-red-500", bg: "from-red-600 to-red-700", icon: AlertTriangle }
    if (level === "high" || riskScore >= 60) 
      return { label: "High Risk", color: "text-orange-500", bg: "from-orange-500 to-red-500", icon: AlertTriangle }
    if (level === "medium" || riskScore >= 40) 
      return { label: "Medium Risk", color: "text-yellow-400", bg: "from-yellow-500 to-orange-500", icon: Shield }
    return { label: "Low Risk", color: "text-green-400", bg: "from-green-500 to-emerald-500", icon: Shield }
  }

  const risk = getRiskLevel()
  const RiskIcon = risk.icon
  const riskData = [{ name: "Risk", value: riskScore }]

  const getProbabilityColor = (prob) => {
    const p = prob?.toLowerCase()
    if (p === "high") return "text-red-400 bg-red-500/20"
    if (p === "medium") return "text-yellow-400 bg-yellow-500/20"
    return "text-blue-400 bg-blue-500/20"
  }

  return (
    <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-8 backdrop-blur">
      <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
        <TrendingUp className="w-5 h-5 text-cyan-400" />
        AI Risk Assessment
      </h2>

      <div className="flex flex-col items-center gap-6">
        <div className="relative w-56 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={riskData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                dataKey="value"
                startAngle={90}
                endAngle={450}
              >
                <Cell fill="#06b6d4" />
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-4xl font-bold text-white">{riskScore}</span>
            <span className="text-slate-400 text-sm">/100</span>
          </div>
        </div>

        <div className="text-center">
          <div className={`flex items-center justify-center gap-2 mb-2`}>
            <RiskIcon className={`w-5 h-5 ${risk.color}`} />
            <p className={`text-xl font-semibold ${risk.color}`}>{risk.label}</p>
          </div>
          {isQuotaError && (
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-3 mb-3">
              <p className="text-orange-400 text-sm font-semibold mb-1">⚠️ API Quota Exceeded</p>
              <p className="text-slate-400 text-xs">Free tier limit: 20 requests/day. Wait for reset or upgrade plan.</p>
            </div>
          )}
          {riskSummary && (
            <p className={`text-slate-400 text-sm max-w-md ${isQuotaError ? 'mt-2' : ''}`}>{riskSummary}</p>
          )}
        </div>

        <div className="w-full h-2 bg-slate-700/50 rounded-full overflow-hidden">
          <div 
            className={`h-full bg-gradient-to-r ${risk.bg} rounded-full transition-all`}
            style={{ width: `${riskScore}%` }}
          ></div>
        </div>

        <div className="w-full space-y-3">
          <div className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
            <span className="text-slate-300 text-sm">Total Open Ports:</span>
            <span className="text-white font-semibold">{openPortsCount}</span>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
            <span className="text-slate-300 text-sm">Vulnerabilities Found:</span>
            <span className="text-white font-semibold">{data?.data?.vulnerabilities_found || 0}</span>
          </div>
        </div>

        {/* Most Likely Attacks */}
        {mostLikelyAttacks && mostLikelyAttacks.length > 0 && (
          <div className="w-full mt-4">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              Most Likely Attack Vectors
            </h3>
            <div className="space-y-2">
              {mostLikelyAttacks.slice(0, 3).map((attack, idx) => (
                <div key={idx} className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-white text-sm font-medium">{attack.attack_type}</span>
                    <span className={`text-xs px-2 py-0.5 rounded ${getProbabilityColor(attack.probability)}`}>
                      {attack.probability}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs">{attack.reason}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
