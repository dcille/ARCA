'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/auth'

export default function Home() {
  const router = useRouter()
  const { token } = useAuthStore()

  useEffect(() => {
    if (token) {
      router.push('/darca/overview')
    } else {
      router.push('/auth/sign-in')
    }
  }, [token, router])

  return (
    <div className="min-h-screen flex items-center justify-center bg-brand-navy">
      <div className="text-center">
        <h1 className="text-5xl font-bold text-white mb-2">D-ARCA</h1>
        <p className="text-brand-teal text-lg">Asset Risk & Cloud Analysis</p>
        <div className="mt-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-green mx-auto"></div>
        </div>
      </div>
    </div>
  )
}
