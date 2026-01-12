import { Shield, User } from "lucide-react"

export default function Header() {
  return (
    <header className="border-b border-slate-700/50 bg-slate-900/50 backdrop-blur-md">
      <div className="container mx-auto flex items-center justify-between px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 p-2">
            <Shield size={24} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">WebReconX</h1>
        </div>

        <nav className="hidden gap-8 md:flex">
          <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
            Home
          </a>
          <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
            Features
          </a>
          <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
            Features
          </a>
          <a href="#" className="text-slate-300 hover:text-cyan-400 transition">
            Report History
          </a>
        </nav>

        <div className="flex items-center gap-4">
          <button className="rounded-full p-2 hover:bg-slate-800 transition">
            <User size={20} className="text-slate-400" />
          </button>
          <button className="text-slate-300 hover:text-cyan-400 transition text-sm font-medium">Logout</button>
        </div>
      </div>
    </header>
  )
}
