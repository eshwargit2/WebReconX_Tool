import { AlertCircle, CheckCircle2, AlertTriangle, ChevronRight, Lightbulb, Wrench } from "lucide-react"

export default function IssuesRecommendations({ data }) {
  const aiAnalysis = data?.ai_analysis
  const vulnerabilities = aiAnalysis?.vulnerabilities || []
  const recommendations = aiAnalysis?.security_recommendations || []
  const complianceNotes = aiAnalysis?.compliance_notes || ""
  const isQuotaError = aiAnalysis?.error === 'quota_exceeded'

  const getSeverityConfig = (severity) => {
    const sev = severity?.toLowerCase()
    if (sev === "critical") 
      return { bg: "bg-red-500/20", badge: "bg-red-600", icon: "text-red-400", iconComp: AlertCircle }
    if (sev === "high") 
      return { bg: "bg-orange-500/20", badge: "bg-orange-600", icon: "text-orange-400", iconComp: AlertTriangle }
    if (sev === "medium") 
      return { bg: "bg-yellow-500/20", badge: "bg-yellow-600", icon: "text-yellow-400", iconComp: AlertTriangle }
    return { bg: "bg-blue-500/20", badge: "bg-blue-600", icon: "text-blue-400", iconComp: AlertCircle }
  }

  const getPriorityConfig = (priority) => {
    const pri = priority?.toLowerCase()
    if (pri === "critical") 
      return { badge: "bg-red-500/30 text-red-400", text: "CRITICAL" }
    if (pri === "high") 
      return { badge: "bg-orange-500/30 text-orange-400", text: "HIGH" }
    if (pri === "medium") 
      return { badge: "bg-yellow-500/30 text-yellow-400", text: "MEDIUM" }
    return { badge: "bg-blue-500/30 text-blue-400", text: "LOW" }
  }

  return (
    <div className="space-y-6">
      {/* Vulnerabilities Section */}
      {vulnerabilities && vulnerabilities.length > 0 && (
        <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-6 backdrop-blur">
          <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-red-400" />
            AI-Identified Vulnerabilities
          </h2>

          <div className="space-y-3">
            {vulnerabilities.map((vuln, idx) => {
              const config = getSeverityConfig(vuln.severity)
              const IconComponent = config.iconComp

              return (
                <div
                  key={idx}
                  className={`${config.bg} rounded-lg p-4 border border-slate-700/50 hover:border-slate-600 transition`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`${config.badge} rounded-full p-2 flex-shrink-0`}>
                      <IconComponent size={18} className={config.icon} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-semibold text-white">{vuln.title}</h3>
                        <span className={`text-xs px-2 py-0.5 rounded ${config.badge.replace('bg-', 'bg-').replace('-600', '-500/30')} ${config.icon}`}>
                          {vuln.severity?.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-slate-300 mb-2">{vuln.description}</p>
                      {vuln.attack_method && (
                        <div className="bg-red-900/20 rounded p-2 mb-2 border border-red-500/30">
                          <p className="text-xs text-red-300">
                            <span className="font-semibold text-red-400">Attack Method:</span> {vuln.attack_method}
                          </p>
                        </div>
                      )}
                      {vuln.impact && (
                        <div className="bg-slate-900/50 rounded p-2 mb-2">
                          <p className="text-xs text-slate-400">
                            <span className="font-semibold text-orange-400">Impact:</span> {vuln.impact}
                          </p>
                        </div>
                      )}
                      {vuln.fix && (
                        <div className="bg-cyan-500/10 border border-cyan-500/30 rounded p-2">
                          <p className="text-xs text-cyan-300">
                            <span className="font-semibold">Fix:</span> {vuln.fix}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Recommendations Section */}
      {recommendations && recommendations.length > 0 && (
        <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-6 backdrop-blur">
          <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
            <Lightbulb className="w-5 h-5 text-yellow-400" />
            AI Security Recommendations
          </h2>

          <div className="space-y-3">
            {recommendations.map((rec, idx) => {
              const config = getPriorityConfig(rec.priority)

              return (
                <div
                  key={idx}
                  className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/50 hover:border-cyan-500/50 transition group cursor-pointer"
                >
                  <div className="flex items-start gap-3">
                    <div className="bg-cyan-500/20 rounded-full p-2 flex-shrink-0">
                      <Wrench size={18} className="text-cyan-400" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <span className="text-xs text-slate-500 font-medium">{rec.category}</span>
                          <h3 className="font-semibold text-white">{rec.recommendation}</h3>
                        </div>
                        <span className={`text-xs px-2 py-0.5 rounded ${config.badge} font-semibold`}>
                          {config.text}
                        </span>
                      </div>
                      {rec.implementation && (
                        <div className="bg-slate-800/50 rounded p-2 mt-2">
                          <p className="text-xs text-slate-300">
                            <span className="font-semibold text-cyan-400">Implementation:</span> {rec.implementation}
                          </p>
                        </div>
                      )}
                    </div>
                    <ChevronRight size={20} className="text-slate-600 group-hover:text-cyan-400 transition flex-shrink-0" />
                  </div>
                </div>
              )
            })}
          </div>

          {complianceNotes && (
            <div className="mt-4 bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
              <p className="text-sm text-blue-300">
                <span className="font-semibold">Compliance Notes:</span> {complianceNotes}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Empty state if no AI data */}
      {(!vulnerabilities || vulnerabilities.length === 0) && (!recommendations || recommendations.length === 0) && (
        <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-8 backdrop-blur text-center">
          {isQuotaError ? (
            <>
              <AlertCircle className="w-12 h-12 text-orange-400 mx-auto mb-3" />
              <h3 className="text-lg font-semibold text-white mb-2">AI Analysis Quota Exceeded</h3>
              <p className="text-slate-400 text-sm mb-3">
                Gemini API free tier limit reached (20 requests/day).
              </p>
              <p className="text-slate-300 text-sm">
                The scan completed successfully but detailed AI insights are unavailable. 
                Your quota will reset in 24 hours, or you can <a href="https://ai.google.dev/pricing" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">upgrade your plan</a> for higher limits.
              </p>
            </>
          ) : (
            <>
              <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto mb-3" />
              <h3 className="text-lg font-semibold text-white mb-2">No Major Issues Detected</h3>
              <p className="text-slate-400 text-sm">
                The security scan completed successfully. Enable AI analysis with Gemini API key for detailed recommendations.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  )
}
