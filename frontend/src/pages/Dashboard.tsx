import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Progress } from '@/components/ui/progress'
import { useToast } from '@/hooks/use-toast'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { 
  Sparkles, 
  History, 
  Settings, 
  LogOut, 
  Gift, 
  MapPin, 
  DollarSign, 
  User,
  Loader2,
  Search
} from 'lucide-react'

const DEMO_CHAT = `[11/15/24] Partner: Ugh, my lower back is killing me after that long drive yesterday.
[11/16/24] Partner: My eyes feel so strained from staring at screens all day.
[11/18/24] Partner: This chair is destroying my posture.
[11/20/24] Partner: My feet are freezing in these thin socks.
[11/21/24] Partner: Neck pain again, need to stretch more.
[11/22/24] Partner: This lighting is giving me migraines.
[11/26/24] Partner: Motivation is zero today, feeling burned out.
[12/01/24] Partner: My neck is so stiff from this laptop screen.
[12/02/24] Partner: I'm freezing in this office, the AC is too strong.
[12/03/24] Partner: Sitting down all day is making me feel so sluggish.`

export function Dashboard() {
  const navigate = useNavigate()
  const { user, logout } = useAuthStore()
  const { toast } = useToast()
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progress, setProgress] = useState(0)
  
  const [formData, setFormData] = useState({
    recipient: 'Partner',
    location: 'Lagos, Nigeria',
    budget: '100',
    currency: 'USD',
    chat_log: '',
    max_results: 4,
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsAnalyzing(true)
    setProgress(10)

    try {
      setProgress(30)
      const { data } = await api.post('/api/analyze', formData)
      setProgress(100)

      navigate({
        to: '/results/$analysisId',
        params: { analysisId: data.analysis_id.toString() },
      })
    } catch (error: any) {
      const message = error.response?.data?.error || 'Analysis failed'
      
      if (error.response?.status === 429) {
        toast({
          title: 'Rate limit exceeded',
          description: 'Upgrade to Pro for more searches',
          variant: 'destructive',
        })
        navigate({ to: '/settings' })
      } else {
        toast({
          title: 'Error',
          description: message,
          variant: 'destructive',
        })
      }
    } finally {
      setIsAnalyzing(false)
    }
  }

  const loadDemo = () => {
    setFormData({ ...formData, chat_log: DEMO_CHAT })
  }

  const handleLogout = () => {
    logout()
    navigate({ to: '/login' })
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-600 to-indigo-600 flex items-center justify-center">
              <Gift className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-xl">Gift Recommender</span>
          </div>

          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => navigate({ to: '/history' })}
            >
              <History className="w-4 h-4 mr-2" />
              History
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="relative h-8 w-8 rounded-full">
                  <Avatar className="h-8 w-8">
                    <AvatarImage src={user?.avatar} alt={user?.name} />
                    <AvatarFallback>{user?.name?.[0]}</AvatarFallback>
                  </Avatar>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56" align="end" forceMount>
                <div className="flex items-center gap-2 p-2">
                  <div className="flex flex-col space-y-1 leading-none">
                    <p className="font-medium">{user?.name}</p>
                    <p className="w-[200px] truncate text-sm text-muted-foreground">
                      {user?.email}
                    </p>
                  </div>
                </div>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => navigate({ to: '/settings' })}>
                  <Settings className="mr-2 h-4 w-4" />
                  Settings
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout}>
                  <LogOut className="mr-2 h-4 w-4" />
                  Log out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid lg:grid-cols-3 gap-8">
          {/* Main Form */}
          <div className="lg:col-span-2 space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-purple-600" />
                  New Analysis
                </CardTitle>
                <CardDescription>
                  Paste a WhatsApp chat or describe someone's complaints
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="grid sm:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="recipient" className="flex items-center gap-2">
                        <User className="w-4 h-4" />
                        Recipient Name
                      </Label>
                      <Input
                        id="recipient"
                        value={formData.recipient}
                        onChange={(e) => setFormData({ ...formData, recipient: e.target.value })}
                        placeholder="Partner, Friend, Mom..."
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="location" className="flex items-center gap-2">
                        <MapPin className="w-4 h-4" />
                        Their Location
                      </Label>
                      <Input
                        id="location"
                        value={formData.location}
                        onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                        placeholder="Lagos, Nigeria"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="budget" className="flex items-center gap-2">
                        <DollarSign className="w-4 h-4" />
                        Budget
                      </Label>
                      <Input
                        id="budget"
                        type="number"
                        value={formData.budget}
                        onChange={(e) => setFormData({ ...formData, budget: e.target.value })}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label>Currency</Label>
                      <Select
                        value={formData.currency}
                        onValueChange={(v) => setFormData({ ...formData, currency: v })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="USD">USD ($)</SelectItem>
                          <SelectItem value="EUR">EUR (€)</SelectItem>
                          <SelectItem value="GBP">GBP (£)</SelectItem>
                          <SelectItem value="NGN">NGN (₦)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="chat">Chat Log or Complaints</Label>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={loadDemo}
                      >
                        Load demo data
                      </Button>
                    </div>
                    <Textarea
                      id="chat"
                      value={formData.chat_log}
                      onChange={(e) => setFormData({ ...formData, chat_log: e.target.value })}
                      placeholder="[12/01/24] Partner: My neck is so stiff...
[12/02/24] Partner: I'm freezing in this office..."
                      className="min-h-[200px] font-mono text-sm"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Search Depth (results per query)</Label>
                    <div className="flex items-center gap-4">
                      <input
                        type="range"
                        min="1"
                        max="10"
                        value={formData.max_results}
                        onChange={(e) => setFormData({ ...formData, max_results: parseInt(e.target.value) })}
                        className="flex-1"
                      />
                      <span className="w-12 text-center font-medium">{formData.max_results}</span>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Higher = more options but uses more API quota
                    </p>
                  </div>

                  {isAnalyzing && (
                    <div className="space-y-2">
                      <Progress value={progress} className="h-2" />
                      <p className="text-sm text-center text-muted-foreground">
                        {progress < 30 ? 'Analyzing pain points...' : 
                         progress < 100 ? 'Searching for gifts...' : 
                         'Finalizing results...'}
                      </p>
                    </div>
                  )}

                  <Button
                    type="submit"
                    className="w-full"
                    size="lg"
                    disabled={isAnalyzing || !formData.chat_log}
                  >
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4 mr-2" />
                        Find Perfect Gifts
                      </>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar Info */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>How it works</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center shrink-0">
                    <span className="text-sm font-bold text-purple-600">1</span>
                  </div>
                  <div>
                    <p className="font-medium">AI Analysis</p>
                    <p className="text-sm text-muted-foreground">
                      Gemini AI extracts pain points from your chat
                    </p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center shrink-0">
                    <span className="text-sm font-bold text-purple-600">2</span>
                  </div>
                  <div>
                    <p className="font-medium">Smart Search</p>
                    <p className="text-sm text-muted-foreground">
                      Brave finds products in their location
                    </p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center shrink-0">
                    <span className="text-sm font-bold text-purple-600">3</span>
                  </div>
                  <div>
                    <p className="font-medium">Curated Matches</p>
                    <p className="text-sm text-muted-foreground">
                      Budget-friendly options ranked by relevance
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Your Plan</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between mb-2">
                  <span className="capitalize font-medium">{user?.subscription_tier || 'Free'}</span>
                  <span className="text-sm text-muted-foreground">50 searches/mo</span>
                </div>
                <Progress value={30} className="h-2" />
                <p className="text-sm text-muted-foreground mt-2">
                  15 of 50 searches used this month
                </p>
                <Button
                  variant="outline"
                  className="w-full mt-4"
                  onClick={() => navigate({ to: '/settings' })}
                >
                  Upgrade to Pro
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  )
}
