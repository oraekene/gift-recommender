import { useState, useEffect } from 'react'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'
import { useToast } from '@/hooks/use-toast'
import { Check, CreditCard, Key, Zap } from 'lucide-react'

export function Settings() {
  const { user, updateUser } = useAuthStore()
  const { toast } = useToast()
  const [keys, setKeys] = useState({ brave: '', nvidia: '', has_keys: false })
  const [subscription, setSubscription] = useState({
    tier: 'free',
    searches_this_month: 0,
    search_limit: 50,
    total_analyses: 0,
  })
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    try {
      const [keysRes, subRes] = await Promise.all([
        api.get('/api/user/keys'),
        api.get('/api/user/subscription'),
      ])
      setKeys(keysRes.data)
      setSubscription(subRes.data)
    } catch (error) {
      console.error('Failed to load settings:', error)
    }
  }

  const handleUpdateKeys = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    try {
      await api.post('/api/user/keys', {
        brave_api_key: keys.brave,
        nvidia_api_key: keys.nvidia,
      })
      updateUser({ has_api_keys: true })
      toast({ title: 'Keys updated successfully' })
      fetchData()
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.response?.data?.error || 'Failed to update keys',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleCheckout = async (tier: string) => {
    try {
      const { data } = await api.post('/api/stripe/checkout', { tier })
      window.location.href = data.url
    } catch (error) {
      toast({ title: 'Checkout failed', variant: 'destructive' })
    }
  }

  const handlePortal = async () => {
    try {
      const { data } = await api.post('/api/stripe/portal')
      window.location.href = data.url
    } catch (error) {
      toast({ title: 'Billing portal unavailable', variant: 'destructive' })
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4">
      <div className="max-w-4xl mx-auto space-y-8">
        <div>
          <h1 className="text-3xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Manage your API keys and subscription</p>
        </div>

        {/* API Keys */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="w-5 h-5" />
              API Keys
            </CardTitle>
            <CardDescription>
              Your keys are encrypted and never shared
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleUpdateKeys} className="space-y-4">
              <div className="space-y-2">
                <Label>Brave Search API Key</Label>
                <Input
                  type="password"
                  value={keys.brave}
                  onChange={(e) => setKeys({ ...keys, brave: e.target.value })}
                  placeholder={keys.has_keys ? '••••••••••••••••' : 'Enter your Brave API key'}
                />
              </div>
              <div className="space-y-2">
                <Label>NVIDIA API Key (Kimi K2.5)</Label>
                <Input
                  type="password"
                  value={keys.nvidia}
                  onChange={(e) => setKeys({ ...keys, nvidia: e.target.value })}
                  placeholder={keys.has_keys ? '••••••••••••••••' : 'Enter your NVIDIA API key (nvapi-...)'}
                />
              </div>
              <Button type="submit" disabled={isLoading}>
                {isLoading ? 'Saving...' : 'Update Keys'}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Usage */}
        <Card>
          <CardHeader>
            <CardTitle>Usage This Month</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between text-sm">
              <span>{subscription.searches_this_month} searches used</span>
              <span>{subscription.search_limit} limit</span>
            </div>
            <Progress
              value={(subscription.searches_this_month / subscription.search_limit) * 100}
            />
            <p className="text-sm text-muted-foreground">
              Total analyses: {subscription.total_analyses}
            </p>
          </CardContent>
        </Card>

        {/* Subscription */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CreditCard className="w-5 h-5" />
              Subscription
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-3 gap-4">
              {/* Free Plan */}
              <div className={`p-4 rounded-lg border-2 ${subscription.tier === 'free' ? 'border-purple-600 bg-purple-50' : 'border-gray-200'}`}>
                <h3 className="font-semibold mb-2">Free</h3>
                <p className="text-2xl font-bold mb-4">$0</p>
                <ul className="text-sm space-y-2 mb-4">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    50 searches/month
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    Basic analysis
                  </li>
                </ul>
                {subscription.tier === 'free' ? (
                  <Button disabled className="w-full">Current Plan</Button>
                ) : (
                  <Button variant="outline" className="w-full" onClick={handlePortal}>
                    Downgrade
                  </Button>
                )}
              </div>

              {/* Pro Plan */}
              <div className={`p-4 rounded-lg border-2 ${subscription.tier === 'pro' ? 'border-purple-600 bg-purple-50' : 'border-gray-200'}`}>
                <h3 className="font-semibold mb-2">Pro</h3>
                <p className="text-2xl font-bold mb-4">$9<span className="text-sm font-normal">/mo</span></p>
                <ul className="text-sm space-y-2 mb-4">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    500 searches/month
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    Priority analysis
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    History export
                  </li>
                </ul>
                {subscription.tier === 'pro' ? (
                  <Button disabled className="w-full">Current Plan</Button>
                ) : (
                  <Button className="w-full" onClick={() => handleCheckout('pro')}>
                    <Zap className="w-4 h-4 mr-2" />
                    Upgrade
                  </Button>
                )}
              </div>

              {/* Enterprise Plan */}
              <div className={`p-4 rounded-lg border-2 ${subscription.tier === 'enterprise' ? 'border-purple-600 bg-purple-50' : 'border-gray-200'}`}>
                <h3 className="font-semibold mb-2">Enterprise</h3>
                <p className="text-2xl font-bold mb-4">$29<span className="text-sm font-normal">/mo</span></p>
                <ul className="text-sm space-y-2 mb-4">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    5,000 searches/month
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    API access
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    Dedicated support
                  </li>
                </ul>
                {subscription.tier === 'enterprise' ? (
                  <Button disabled className="w-full">Current Plan</Button>
                ) : (
                  <Button className="w-full" onClick={() => handleCheckout('enterprise')}>
                    Contact Sales
                  </Button>
                )}
              </div>
            </div>

            {subscription.tier !== 'free' && (
              <Button variant="outline" className="mt-4 w-full" onClick={handlePortal}>
                Manage Billing
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
