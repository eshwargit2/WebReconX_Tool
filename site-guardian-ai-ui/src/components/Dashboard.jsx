import WebsiteOverview from "./WebsiteOverview"
import RiskAssessment from "./RiskAssessment"
import TechnologyStack from "./TechnologyStack"
import IssuesRecommendations from "./IssuesRecommendations"
import { FileDown } from "lucide-react"

export default function Dashboard({ data }) {
  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <WebsiteOverview data={data} />
        <div className="lg:col-span-2 space-y-8">
          <TechnologyStack data={data} />
          <RiskAssessment data={data} />
        </div>
      </div>

      <IssuesRecommendations data={data} />

      {/* <div className="flex justify-center pt-8 pb-4">
        <button className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 text-white px-8 py-3 rounded-lg font-semibold transition">
          <FileDown size={20} />
          Generate PDF Report
        </button>
      </div>

      <footer className="text-center text-sm text-slate-500 py-8 border-t border-slate-700/50">
        © 2025 SiteGuardian All. Share___reitgrified
      </footer> */}
    </div>
  )
}
