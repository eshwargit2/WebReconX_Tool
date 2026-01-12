import { AlertCircle, AlertTriangle, CheckCircle2, ChevronRight } from "lucide-react"

const issues = [
  {
    id: 1,
    type: "critical",
    icon: AlertCircle,
    title: "Outdated Nginx Version",
    description: "Has doolk Cogist. known vulnerabilities.",
  },
  {
    id: 2,
    type: "critical",
    icon: AlertCircle,
    title: "Potential SQL Injection",
    description: "Running Nginx 1.2.0 which has known issue in the latest stable version (e., [12.%)",
  },
  {
    id: 3,
    type: "warning",
    icon: AlertTriangle,
    title: "Exposed Network Service",
    description:
      "Likely to harbor changed in giants. Recommended Action: permission ciphers and items to close unrequired ports.",
  },
  {
    id: 4,
    type: "success",
    icon: CheckCircle2,
    title: "Strong HTTPS Enforced",
    description:
      "Rebted uses HTTP/7 prefer and TLS3 open. Recommend Action access UHT Class or dice time unnecessary ports.",
  },
  {
    id: 5,
    type: "success",
    icon: CheckCircle2,
    title: "Strong HTTPS Enfomced",
    description: "Maintain use current configuration.",
  },
]

export default function IssuesAndRecommendations() {
  return (
    <div className="bg-card rounded-lg p-6 border border-border">
      <h2 className="text-xl font-bold text-foreground mb-6">Identified Issues & Recommendations</h2>
      <div className="space-y-3">
        {issues.map((issue) => {
          const IconComponent = issue.icon
          const isSuccess = issue.type === "success"
          const isWarning = issue.type === "warning"

          let bgColor = "bg-red-500/10"
          let iconColor = "text-red-500"

          if (isSuccess) {
            bgColor = "bg-green-500/10"
            iconColor = "text-green-500"
          } else if (isWarning) {
            bgColor = "bg-orange-500/10"
            iconColor = "text-orange-500"
          }

          return (
            <div
              key={issue.id}
              className={`${bgColor} rounded-lg p-4 flex gap-4 hover:bg-opacity-80 transition-colors cursor-pointer group`}
            >
              <IconComponent className={`w-5 h-5 flex-shrink-0 mt-0.5 ${iconColor}`} />
              <div className="flex-1 min-w-0">
                <p className="font-medium text-foreground text-sm">{issue.title}</p>
                <p className="text-xs text-muted-foreground mt-1">{issue.description}</p>
              </div>
              <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-accent transition-colors flex-shrink-0 mt-0.5" />
            </div>
          )
        })}
      </div>
    </div>
  )
}
