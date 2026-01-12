import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts"

export default function RiskAssessment({ data }) {
  const riskScore = data?.data?.risk_score || 0
  const openPortsCount = data?.total_open_ports || 0
  
  // Calculate risk level based on score and open ports
  const getRiskLevel = () => {
    if (riskScore >= 80 || openPortsCount > 10) return { label: "High Risk", color: "text-red-500", bg: "from-red-500 to-red-600" }
    if (riskScore >= 50 || openPortsCount > 5) return { label: "Medium Risk", color: "text-orange-400", bg: "from-orange-500 to-red-500" }
    return { label: "Low Risk", color: "text-green-400", bg: "from-green-500 to-emerald-500" }
  }

  const riskLevel = getRiskLevel()
  const riskData = [{ name: "Risk", value: riskScore }]

  return (
    <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-8 backdrop-blur">
      <h2 className="text-xl font-bold text-white mb-8">AI Risk Assessment</h2>

      <div className="flex flex-col items-center gap-8">
        <div className="relative w-64 h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={riskData}
                cx="50%"
                cy="50%"
                innerRadius={70}
                outerRadius={100}
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
            <span className="text-slate-400">/100</span>
          </div>
        </div>

        <div className="text-center">
          <p className="text-slate-400 text-sm">Status:</p>
          <p className={`text-xl font-semibold ${riskLevel.color}`}>{riskLevel.label}</p>
        </div>

        <div className="w-full h-2 bg-slate-700/50 rounded-full overflow-hidden">
          <div 
            className={`h-full bg-gradient-to-r ${riskLevel.bg} rounded-full transition-all`}
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

        {data && (
          <p className="text-slate-300 text-sm leading-relaxed text-center max-w-md">
            {openPortsCount > 0 
              ? `Scan detected ${openPortsCount} open port${openPortsCount !== 1 ? 's' : ''} on ${data.url}. Some exposed services may pose security risks.`
              : `No open ports detected on ${data.url}. The server appears well-secured.`
            }
          </p>
        )}
      </div>
    </div>
  )
}
