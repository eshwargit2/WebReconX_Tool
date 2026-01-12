import { Globe, Server, Code, Database, Network, Lock, Wifi } from "lucide-react"

const overviewItems = [
  {
    icon: Globe,
    label: "IP Address",
    value: "202.0.113.7",
  },
  {
    icon: Server,
    label: "Hosting",
    value: "Cloudflare, USA",
  },
  {
    icon: Code,
    label: "Frontend",
    value: "Server details",
  },
  {
    icon: Database,
    label: "Backend",
    value: "Node.js, Express",
  },
  {
    icon: Server,
    label: "Frontend",
    value: "React, Next.js",
  },
  {
    icon: Network,
    label: "Web Server",
    value: "Nginx/1.22.0",
  },
  {
    icon: Lock,
    label: "Webs",
    value: "Render/forGJUnetsbda",
  },
  {
    icon: Server,
    label: "Web Server",
    value: "Deps/210",
  },
  {
    icon: Wifi,
    label: "Web WebSocket",
    value: "config...",
  },
]

export default function WebsiteOverview() {
  return (
    <div className="bg-card rounded-lg p-6 border border-border">
      <h2 className="text-xl font-bold text-foreground mb-6">Website Overview</h2>
      <div className="space-y-4">
        {overviewItems.map((item, index) => {
          const IconComponent = item.icon
          return (
            <div
              key={index}
              className="flex items-start gap-4 pb-4 border-b border-border/50 last:border-b-0 last:pb-0"
            >
              <div className="bg-primary/10 p-2 rounded-lg flex-shrink-0">
                <IconComponent className="w-5 h-5 text-accent" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs text-muted-foreground">{item.label}</p>
                <p className="text-sm font-medium text-foreground truncate">{item.value}</p>
              </div>
              <button className="text-muted-foreground hover:text-accent transition-colors flex-shrink-0">
                <Lock className="w-4 h-4" />
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
