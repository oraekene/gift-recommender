import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import {
  ArrowLeft,
  ExternalLink,
  Sparkles,
  Gift,
  TrendingUp,
  MapPin,
  DollarSign,
  Search,
  Loader2,
  X
} from 'lucide-react'

interface PainPoint {
  pain_point: string
  score: number
  category: string
  trigger_text: string
  context: string
}

interface GiftItem {
  strategy: string
  solution_item: string
  product: string
  price_guess: string
  url: string
  reason: string
  pain_point: string
  pain_score: number
}

interface Alternative {
  product: string
  price_guess: string
  url: string
  reason: string
}

export function Results() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const [data, setData] = useState<{
    pains: PainPoint[]
    gifts: GiftItem[]
    search_count: number
    recipient: string
    location: string
    budget: string
    currency: string
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [searchingIdx, setSearchingIdx] = useState<number | null>(null)
  const [alternatives, setAlternatives] = useState<Record<number, Alternative[]>>({})

  useEffect(() => {
    const fetchData = async () => {
      try {
        const { data: response } = await api.get(`/api/history/${analysisId}`)
        setData(response)
      } catch (error) {
        console.error('Failed to load results:', error)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [analysisId])

  const handleMoreLikeThis = async (gift: GiftItem, idx: number) => {
    if (searchingIdx !== null) return
    setSearchingIdx(idx)
    try {
      const { data: response } = await api.post('/api/search-similar', {
        product: gift.product,
        pain_point: gift.pain_point,
        budget: data?.budget || '100',
        currency: data?.currency || 'USD',
        location: data?.location || '',
      })
      setAlternatives((prev) => ({ ...prev, [idx]: response.alternatives || [] }))
    } catch (error) {
      console.error('Search similar failed:', error)
    } finally {
      setSearchingIdx(null)
    }
  }

  const dismissAlternatives = (idx: number) => {
    setAlternatives((prev) => {
      const next = { ...prev }
      delete next[idx]
      return next
    })
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Sparkles className="w-12 h-12 animate-pulse text-purple-600 mx-auto mb-4" />
          <p className="text-lg font-medium">Loading results...</p>
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Card>
          <CardContent className="pt-6 text-center">
            <p className="text-lg font-medium mb-4">Analysis not found</p>
            <Button onClick={() => navigate('/dashboard')}>
              Back to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const getStrategyColor = (strategy: string) => {
    const colors: Record<string, string> = {
      practical: 'bg-blue-100 text-blue-800',
      splurge: 'bg-purple-100 text-purple-800',
      thoughtful: 'bg-pink-100 text-pink-800',
    }
    return colors[strategy] || 'bg-gray-100 text-gray-800'
  }

  return (
    <div className="min-h-screen bg-gray-50 pb-12">
      {/* Header */}
      <header className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Button
            variant="ghost"
            onClick={() => navigate('/dashboard')}
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <MapPin className="w-4 h-4" />
            {data.location}
            <span className="mx-2">•</span>
            <DollarSign className="w-4 h-4" />
            {data.budget} {data.currency}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">
            Gift Recommendations for {data.recipient}
          </h1>
          <p className="text-muted-foreground">
            Based on {data.pains.length} detected pain points • {data.search_count} searches performed
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Pain Points */}
          <div>
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Detected Issues
            </h2>
            <div className="space-y-3">
              {data.pains.map((pain, idx) => (
                <Card key={idx} className="border-l-4 border-l-purple-500">
                  <CardContent className="pt-4">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <p className="font-medium">{pain.pain_point}</p>
                        <p className="text-sm text-muted-foreground">{pain.category}</p>
                      </div>
                      <div className="text-right">
                        <span className="text-2xl font-bold text-purple-600">
                          {pain.score}
                        </span>
                        <span className="text-sm text-muted-foreground">/10</span>
                      </div>
                    </div>
                    <Progress value={pain.score * 10} className="h-2" />
                    <p className="text-sm text-muted-foreground mt-2 italic">
                      "{pain.trigger_text}"
                    </p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>

          {/* Gift Recommendations */}
          <div className="lg:col-span-2">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Gift className="w-5 h-5" />
              Curated Gifts
            </h2>
            <div className="space-y-4">
              {data.gifts.map((gift, idx) => (
                <div key={idx}>
                  <Card className="overflow-hidden hover:shadow-lg transition-shadow">
                    <CardContent className="p-6">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <Badge className={`mb-2 ${getStrategyColor(gift.strategy)}`}>
                            {gift.strategy}
                          </Badge>
                          <h3 className="text-xl font-semibold">{gift.product}</h3>
                          <p className="text-sm text-muted-foreground">
                            Solves: {gift.pain_point} (Score: {gift.pain_score}/10)
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-2xl font-bold text-green-600">
                            {gift.price_guess} {data.currency}
                          </p>
                          <p className="text-sm text-muted-foreground">estimated</p>
                        </div>
                      </div>

                      <p className="text-sm text-gray-600 mb-4">{gift.reason}</p>

                      <div className="flex gap-3">
                        <Button asChild>
                          <a href={gift.url} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="w-4 h-4 mr-2" />
                            View Product
                          </a>
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={searchingIdx !== null}
                          onClick={() => handleMoreLikeThis(gift, idx)}
                        >
                          {searchingIdx === idx ? (
                            <>
                              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                              Searching...
                            </>
                          ) : (
                            <>
                              <Search className="w-4 h-4 mr-2" />
                              More like this
                            </>
                          )}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Alternatives panel */}
                  {alternatives[idx] && (
                    <Card className="mt-2 border-dashed border-purple-300 bg-purple-50/50">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <p className="text-sm font-semibold text-purple-700">
                            Similar alternatives
                          </p>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 w-6 p-0"
                            onClick={() => dismissAlternatives(idx)}
                          >
                            <X className="w-4 h-4" />
                          </Button>
                        </div>
                        {alternatives[idx].length === 0 ? (
                          <p className="text-sm text-muted-foreground">
                            No similar products found. Try adjusting your budget.
                          </p>
                        ) : (
                          <div className="space-y-3">
                            {alternatives[idx].map((alt, altIdx) => (
                              <div
                                key={altIdx}
                                className="flex items-start justify-between p-3 bg-white rounded-lg border"
                              >
                                <div className="flex-1 mr-4">
                                  <p className="font-medium text-sm">{alt.product}</p>
                                  <p className="text-xs text-muted-foreground mt-1">
                                    {alt.reason}
                                  </p>
                                </div>
                                <div className="text-right shrink-0">
                                  <p className="font-bold text-green-600 text-sm">
                                    {alt.price_guess} {data.currency}
                                  </p>
                                  <a
                                    href={alt.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs text-purple-600 hover:underline inline-flex items-center gap-1 mt-1"
                                  >
                                    View <ExternalLink className="w-3 h-3" />
                                  </a>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  )}
                </div>
              ))}
            </div>

            {/* Stats */}
            <Card className="mt-6 bg-gradient-to-r from-purple-50 to-indigo-50 border-purple-200">
              <CardContent className="pt-6">
                <div className="grid grid-cols-2 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold text-purple-600">{data.pains.length}</p>
                    <p className="text-sm text-muted-foreground">Pain Points</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-purple-600">{data.search_count}</p>
                    <p className="text-sm text-muted-foreground">Searches</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  )
}
