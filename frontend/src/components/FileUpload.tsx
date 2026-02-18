import { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, X, FileText, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { api } from '@/lib/api'
import { useToast } from '@/hooks/use-toast'

interface FileUploadProps {
  onFileUploaded: (fileId: number, content: string) => void
}

export function FileUpload({ onFileUploaded }: FileUploadProps) {
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [uploadedFile, setUploadedFile] = useState<{id: number, name: string, size: number} | null>(null)
  const { toast } = useToast()

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0]
    if (!file) return

    setUploading(true)
    setProgress(0)

    const formData = new FormData()
    formData.append('file', file)

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setProgress(p => Math.min(p + 10, 90))
      }, 200)

      const { data } = await api.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })

      clearInterval(progressInterval)
      setProgress(100)

      setUploadedFile({
        id: data.file_id,
        name: file.name,
        size: data.file_size
      })

      toast({
        title: 'File uploaded',
        description: `${file.name} ready for analysis`
      })

      // Pass content to parent
      if (data.full_content || data.content_preview) {
        onFileUploaded(data.file_id, data.full_content || data.content_preview)
      }

    } catch (error: any) {
      toast({
        title: 'Upload failed',
        description: error.response?.data?.error || 'Unknown error',
        variant: 'destructive'
      })
    } finally {
      setUploading(false)
    }
  }, [onFileUploaded, toast])

  const clearFile = () => {
    setUploadedFile(null)
    setProgress(0)
  }

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.txt'],
      'application/zip': ['.zip'],
      'text/csv': ['.csv']
    },
    maxSize: 10 * 1024 * 1024, // 10MB
    disabled: uploading
  })

  if (uploadedFile) {
    return (
      <div className="flex items-center gap-3 p-4 bg-green-50 border border-green-200 rounded-lg">
        <FileText className="w-8 h-8 text-green-600" />
        <div className="flex-1">
          <p className="font-medium text-green-900">{uploadedFile.name}</p>
          <p className="text-sm text-green-700">
            {(uploadedFile.size / 1024).toFixed(1)} KB • Ready for analysis
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={clearFile}>
          <X className="w-4 h-4" />
        </Button>
      </div>
    )
  }

  return (
    <div
      {...getRootProps()}
      className={`
        border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors
        ${isDragActive ? 'border-purple-500 bg-purple-50' : 'border-gray-300 hover:border-gray-400'}
        ${uploading ? 'pointer-events-none opacity-50' : ''}
      `}
    >
      <input {...getInputProps()} />
      
      {uploading ? (
        <div className="space-y-3">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-purple-600" />
          <Progress value={progress} className="w-full" />
          <p className="text-sm text-gray-600">Uploading to secure storage...</p>
        </div>
      ) : (
        <>
          <Upload className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-lg font-medium mb-2">
            {isDragActive ? 'Drop file here' : 'Drag & drop WhatsApp export'}
          </p>
          <p className="text-sm text-gray-500 mb-4">
            Supports .txt, .zip (WhatsApp export), .csv
          </p>
          <Button type="button" variant="outline">
            Select File
          </Button>
        </>
      )}
    </div>
  )
}
