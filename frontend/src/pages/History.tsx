import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { ArrowLeft, Gift, MapPin, Calendar, Loader2 } from 'lucide-react'

interface HistoryItem {
    id: number
    recipient: string
    location: string
    budget: number
    currency: string
    gift_count: number
    created_at: string
}

export function History() {
    const navigate = useNavigate()
    const [analyses, setAnalyses] = useState<HistoryItem[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const { data } = await api.get('/api/history')
                setAnalyses(data)
            } catch (error) {
                console.error('Failed to load history:', error)
            } finally {
                setLoading(false)
            }
        }
        fetchHistory()
    }, [])

    const formatDate = (iso: string) => {
        const d = new Date(iso)
        return d.toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        })
    }

    return (
        <div className="min-h-screen bg-gray-50">
            <header className="bg-white border-b">
                <div className="max-w-4xl mx-auto px-4 h-16 flex items-center">
                    <Button variant="ghost" onClick={() => navigate('/dashboard')}>
                        <ArrowLeft className="w-4 h-4 mr-2" />
                        Back
                    </Button>
                    <h1 className="text-xl font-bold ml-4">Analysis History</h1>
                </div>
            </header>

            <main className="max-w-4xl mx-auto px-4 py-8">
                {loading ? (
                    <div className="flex items-center justify-center py-20">
                        <Loader2 className="w-8 h-8 animate-spin text-purple-600" />
                    </div>
                ) : analyses.length === 0 ? (
                    <Card>
                        <CardContent className="py-16 text-center">
                            <Gift className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                            <h2 className="text-xl font-semibold mb-2">No analyses yet</h2>
                            <p className="text-muted-foreground mb-6">
                                Run your first analysis to see gift recommendations here.
                            </p>
                            <Button onClick={() => navigate('/dashboard')}>
                                Start an Analysis
                            </Button>
                        </CardContent>
                    </Card>
                ) : (
                    <div className="space-y-3">
                        {analyses.map((item) => (
                            <Card
                                key={item.id}
                                className="cursor-pointer hover:shadow-md transition-shadow"
                                onClick={() => navigate(`/results/${item.id}`)}
                            >
                                <CardContent className="p-5 flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-full bg-purple-100 flex items-center justify-center">
                                            <Gift className="w-5 h-5 text-purple-600" />
                                        </div>
                                        <div>
                                            <p className="font-semibold">{item.recipient}</p>
                                            <div className="flex items-center gap-3 text-sm text-muted-foreground">
                                                <span className="flex items-center gap-1">
                                                    <MapPin className="w-3 h-3" />
                                                    {item.location}
                                                </span>
                                                <span>•</span>
                                                <span>{item.budget} {item.currency}</span>
                                                <span>•</span>
                                                <span>{item.gift_count} gifts</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="text-sm text-muted-foreground flex items-center gap-1">
                                        <Calendar className="w-3 h-3" />
                                        {formatDate(item.created_at)}
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                )}
            </main>
        </div>
    )
}
