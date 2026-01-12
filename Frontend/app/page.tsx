import Header from "@/components/header"
import SearchSection from "@/components/search-section"
import Dashboard from "@/components/dashboard"

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <SearchSection />
        <Dashboard />
      </main>
    </div>
  )
}
