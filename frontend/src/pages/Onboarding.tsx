import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Sparkles } from 'lucide-react'

export function Onboarding() {
  const navigate = useNavigate()

  useEffect(() => {
    // API keys are now app-level — redirect straight to dashboard
    navigate('/dashboard', { replace: true })
  }, [navigate])

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center">
      <div className="text-center">
        <Sparkles className="w-12 h-12 animate-pulse text-purple-600 mx-auto mb-4" />
        <p className="text-lg font-medium">Redirecting to dashboard...</p>
      </div>
    </div>
  )
}
