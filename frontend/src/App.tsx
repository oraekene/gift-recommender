import { RouterProvider, createRouter } from '@tanstack/react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { GoogleOAuthProvider } from '@react-oauth/google'
import { useAuthStore } from '@/store/auth'
import { Login } from '@/pages/Login'
import { Onboarding } from '@/pages/Onboarding'
import { Dashboard } from '@/pages/Dashboard'
import { Results } from '@/pages/Results'
import { Settings } from '@/pages/Settings'

const queryClient = new QueryClient()

// Route definitions
const router = createRouter({
  routeTree: [
    {
      path: '/login',
      component: Login,
    },
    {
      path: '/onboarding',
      component: Onboarding,
    },
    {
      path: '/dashboard',
      component: Dashboard,
    },
    {
      path: '/results/$analysisId',
      component: Results,
    },
    {
      path: '/settings',
      component: Settings,
    },
    {
      path: '/',
      component: () => {
        const { isAuthenticated } = useAuthStore()
        return isAuthenticated ? <Dashboard /> : <Login />
      },
    },
  ],
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <GoogleOAuthProvider clientId={import.meta.env.VITE_GOOGLE_CLIENT_ID}>
        <RouterProvider router={router} />
      </GoogleOAuthProvider>
    </QueryClientProvider>
  )
}

export default App
