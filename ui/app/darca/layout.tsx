'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/auth'
import Sidebar from '@/components/layout/Sidebar'

export default function DarcaLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { token } = useAuthStore()

  useEffect(() => {
    if (!token) {
      router.push('/auth/sign-in')
    }
  }, [token, router])

  if (!token) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-brand-gray-50">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-lg bg-brand-navy flex items-center justify-center">
            <span className="text-brand-green font-bold text-xl">D</span>
          </div>
          <div className="flex gap-1">
            <div className="w-2 h-2 rounded-full bg-brand-green animate-bounce" style={{ animationDelay: '0ms' }} />
            <div className="w-2 h-2 rounded-full bg-brand-green animate-bounce" style={{ animationDelay: '150ms' }} />
            <div className="w-2 h-2 rounded-full bg-brand-green animate-bounce" style={{ animationDelay: '300ms' }} />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen bg-brand-gray-50">
      <Sidebar />
      <main className="flex-1 lg:ml-64 p-4 lg:p-8 pt-16 lg:pt-8 transition-all duration-300">
        {children}
      </main>
    </div>
  )
}
