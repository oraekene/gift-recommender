import { useEffect } from 'react'
import { GoogleLogin, GoogleOAuthProvider } from '@react-oauth/google'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Sparkles, Gift, Heart } from 'lucide-react'

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || ''

export function Login() {
  const navigate = useNavigate()
  const { isAuthenticated, setAuth } = useAuthStore()

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard')
    }
  }, [isAuthenticated, navigate])

  const handleGoogleSuccess = async (credentialResponse: any) => {
    try {
      const { data } = await api.post('/api/auth/google', {
        token: credentialResponse.credential,
      })

      setAuth(data.access_token, data.user)

      if (!data.user.has_api_keys) {
        navigate('/onboarding')
      } else {
        navigate('/dashboard')
      }
    } catch (error) {
      console.error('Auth error:', error)
    }
  }

  return (
    <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
      <div className="min-h-screen bg-gradient-to-br from-violet-600 via-purple-600 to-indigo-800 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/20 backdrop-blur-sm mb-4">
              <Gift className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-4xl font-bold text-white mb-2">Gift Recommender</h1>
            <p className="text-white/80">AI-powered gift suggestions from chat analysis</p>
          </div>

          <Card className="border-0 shadow-2xl">
            <CardHeader className="text-center">
              <CardTitle className="text-2xl">Welcome</CardTitle>
              <CardDescription>
                Sign in to start finding perfect gifts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-center">
                <GoogleLogin
                  onSuccess={handleGoogleSuccess}
                  onError={() => console.log('Login Failed')}
                  size="large"
                  width="300"
                />
              </div>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-background px-2 text-muted-foreground">
                    Features
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="space-y-1">
                  <Sparkles className="w-5 h-5 mx-auto text-purple-600" />
                  <p className="text-xs text-muted-foreground">AI Analysis</p>
                </div>
                <div className="space-y-1">
                  <Heart className="w-5 h-5 mx-auto text-pink-600" />
                  <p className="text-xs text-muted-foreground">Personalized</p>
                </div>
                <div className="space-y-1">
                  <Gift className="w-5 h-5 mx-auto text-indigo-600" />
                  <p className="text-xs text-muted-foreground">Smart Picks</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <p className="text-center text-white/60 text-sm mt-8">
            Free tier: 50 searches/month • No credit card required
          </p>
        </div>
      </div>
    </GoogleOAuthProvider>
  )
}
