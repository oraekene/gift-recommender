import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useToast } from '@/hooks/use-toast'
import { Shield, ExternalLink, Check } from 'lucide-react'

export function Onboarding() {
  const navigate = useNavigate()
  const { user, updateUser } = useAuthStore()
  const { toast } = useToast()
  const [isLoading, setIsLoading] = useState(false)
  const [braveKey, setBraveKey] = useState('')
  const [nvidiaKey, setNvidiaKey] = useState('')  // Changed from geminiKey
  // const [geminiKey, setGeminiKey] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      await api.post('/api/user/keys', {
        brave_api_key: braveKey,
        // gemini_api_key: geminiKey,
        nvidia_api_key: nvidiaKey,  // Changed
      })

      updateUser({ has_api_keys: true })

      toast({
        title: 'Success!',
        description: 'Your API keys have been securely stored.',
      })

      navigate({ to: '/dashboard' })
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.error || 'Failed to save keys',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const skipForNow = () => {
    navigate({ to: '/dashboard' })
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 py-12 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-purple-100 mb-4">
            <Shield className="w-6 h-6 text-purple-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">Secure Setup</h1>
          <p className="text-gray-600 mt-2">
            Add your API keys to enable gift recommendations
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>API Configuration</CardTitle>
            <CardDescription>
              Your keys are encrypted and stored securely. We never share them.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="brave">Brave Search API Key</Label>
                  <a
                    href="https://api.search.brave.com/app/keys"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-purple-600 hover:underline inline-flex items-center gap-1"
                  >
                    Get key <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <Input
                  id="brave"
                  type="password"
                  placeholder="Enter your Brave API key"
                  value={braveKey}
                  onChange={(e) => setBraveKey(e.target.value)}
                />
                <p className="text-sm text-muted-foreground">
                  Free tier: 2,000 searches/month
                </p>
              </div>

              // <div className="space-y-2">
                // <div className="flex items-center justify-between">
                  // <Label htmlFor="gemini">Gemini API Key</Label>
                  // <a
                    // href="https://makersuite.google.com/app/apikey"
                    // target="_blank"
                    // rel="noopener noreferrer"
                    // className="text-sm text-purple-600 hover:underline inline-flex items-center gap-1"
                  // >
                    // Get key <ExternalLink className="w-3 h-3" />
                  // </a>
                // </div>
                // <Input
                  // id="gemini"
                  // type="password"
                  // placeholder="Enter your Gemini API key"
                  // value={geminiKey}
                  // onChange={(e) => setGeminiKey(e.target.value)}
                // />
                // <p className="text-sm text-muted-foreground">
                  // Free tier: 1,500 requests/day
                // </p>
              // </div>

              // Replace Gemini references:
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="nvidia">NVIDIA API Key (Kimi K2.5)</Label>
                  <a
                    href="https://build.nvidia.com/moonshotai/kimi-k2.5"  // Changed URL
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-purple-600 hover:underline inline-flex items-center gap-1"
                  >
                    Get key <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <Input
                  id="nvidia"
                  type="password"
                  placeholder="nvapi-..."
                  value={nvidiaKey}  // Changed state variable
                  onChange={(e) => setNvidiaKey(e.target.value)}
                />
                <p className="text-sm text-muted-foreground">
                  Free tier: 1,000 requests/day via NVIDIA
                </p>
              </div>
            
              <div className="flex gap-4">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={skipForNow}
                >
                  Skip for now
                </Button>
                <Button
                  type="submit"
                  className="flex-1"
                  disabled={isLoading || !braveKey || !geminiKey}
                >
                  {isLoading ? 'Saving...' : (
                    <>
                      <Check className="w-4 h-4 mr-2" />
                      Save & Continue
                    </>
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <div className="mt-8 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <h3 className="font-semibold text-blue-900 mb-2">Why do I need these?</h3>
          <ul className="text-sm text-blue-800 space-y-1">
            <li>• <strong>Brave Search</strong>: Finds real products from across the web</li>
            <li>• <strong>Gemini AI</strong>: Analyzes chats and matches gifts to pain points</li>
            <li>• Both have generous free tiers - no credit card required</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
