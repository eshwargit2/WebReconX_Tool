import { AlertCircle, CheckCircle2, AlertTriangle, ChevronRight } from "lucide-react"

const issues = [
  {
    icon: AlertCircle,
    title: "Outdated Nginx Version",
    description: "Has dock Gigast known vulnerabilities.",
    severity: "critical",
  },
  {
    icon: AlertCircle,
    title: "Potential SQL Injection",
    description: "Running Nellsx 12.5.0 which has known karis in list latest stable version (e. (12.3.)",
    severity: "critical",
  },
  {
    icon: AlertTriangle,
    title: "Exposed! Network Service/i",
    description:
      "Unable to failed/redirect gis susceptible. Recommend: permissional ciphers and lemm to close unnecessary ports.",
    severity: "warning",
  },
  {
    icon: CheckCircle2,
    title: "Strong HTTPS Enforced",
    description:
      "Rebuilt users HTTP / mixed and TLS 3) open. Recommend: Atom access LM dears of dace ume unnecessary ports.",
    severity: "success",
  },
  {
    icon: CheckCircle2,
    title: "Strong HTTPS Enforced",
    description: "Maintain use current configuration.",
    severity: "success",
  },
]

export default function IssuesRecommendations() {
  return (
    <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-8 backdrop-blur">
      <h2 className="text-xl font-bold text-white mb-6">Identified Issues & Recommendations</h2>

      <div className="space-y-4">
        {issues.map((issue, idx) => {
          const IconComponent = issue.icon
          const bgColor =
            issue.severity === "critical"
              ? "bg-red-500/20"
              : issue.severity === "warning"
                ? "bg-orange-500/20"
                : "bg-green-500/20"
          const badgeColor =
            issue.severity === "critical"
              ? "bg-red-600"
              : issue.severity === "warning"
                ? "bg-orange-600"
                : "bg-green-600"
          const iconColor =
            issue.severity === "critical"
              ? "text-red-400"
              : issue.severity === "warning"
                ? "text-orange-400"
                : "text-green-400"

          return (
            <div
              key={idx}
              className={`${bgColor} rounded-lg p-4 border border-slate-700/50 hover:border-slate-600 transition cursor-pointer group`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex gap-3 flex-1">
                  <div className={`${badgeColor} rounded-full p-2 flex-shrink-0`}>
                    <IconComponent size={18} className={iconColor} />
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-white mb-1">{issue.title}</h3>
                    <p className="text-sm text-slate-400">{issue.description}</p>
                  </div>
                </div>
                <ChevronRight size={20} className="text-slate-500 group-hover:text-cyan-400 transition flex-shrink-0" />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
