import { Shield, LogOut } from "lucide-react"

export default function Header() {
  return (
    <header className="border-b border-border bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <div className="bg-primary p-2 rounded-lg">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <h1 className="text-2xl font-bold text-foreground">SiteGuardian AI</h1>
          </div>

          <nav className="hidden md:flex items-center gap-8">
            <a href="#" className="text-foreground hover:text-accent transition-colors">
              Home
            </a>
            <a href="#" className="text-foreground hover:text-accent transition-colors">
              Features
            </a>
            <a href="#" className="text-foreground hover:text-accent transition-colors">
              Features
            </a>
            <a href="#" className="text-foreground hover:text-accent transition-colors">
              Report History
            </a>
          </nav>

          <div className="flex items-center gap-4">
            <button className="text-foreground hover:text-accent transition-colors p-2 rounded-lg hover:bg-accent/10">
              <LogOut className="w-5 h-5" />
            </button>
            <span className="text-sm text-foreground hidden sm:inline">Logout</span>
          </div>
        </div>
      </div>
    </header>
  )
}
