import { Code, Layers, Server, Palette, Box } from "lucide-react"

export default function TechnologyStack({ data }) {
  if (!data || !data.technologies) {
    return null
  }

  const { technologies } = data

  const categoryIcons = {
    "Frontend": Code,
    "CSS Framework": Palette,
    "JS Framework": Layers,
    "Backend": Server,
    "Server": Box
  }

  const categoryColors = {
    "Frontend": "text-blue-400",
    "CSS Framework": "text-pink-400",
    "JS Framework": "text-yellow-400",
    "Backend": "text-green-400",
    "Server": "text-purple-400"
  }

  return (
    <div className="rounded-lg bg-slate-800/50 border border-slate-700/50 p-6 backdrop-blur">
      <h2 className="text-xl font-bold text-white mb-6">Technology Stack</h2>
      
      <div className="space-y-6">
        {Object.entries(technologies).map(([category, techs]) => {
          const IconComponent = categoryIcons[category] || Code
          const colorClass = categoryColors[category] || "text-cyan-400"
          
          return (
            <div key={category} className="space-y-3">
              <div className="flex items-center gap-2">
                <IconComponent size={18} className={colorClass} />
                <h3 className="text-sm font-semibold text-slate-300">{category}</h3>
              </div>
              
              <div className="pl-7 space-y-2">
                {techs.map((tech, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 p-2 rounded bg-slate-700/30 hover:bg-slate-700/50 transition"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                    <span className="text-sm text-slate-200">{tech}</span>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
