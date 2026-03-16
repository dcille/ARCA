'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { api } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline'

export default function SignIn() {
  const router = useRouter()
  const { setAuth } = useAuthStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const data = await api.login(email, password)
      setAuth(data.access_token, data.user)
      toast.success('Welcome back!')
      router.push('/darca/overview')
    } catch (err: any) {
      toast.error(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex">
      {/* Left panel - branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-brand-navy items-center justify-center relative overflow-hidden">
        <div className="absolute inset-0 opacity-10">
          <div className="absolute top-20 left-20 w-64 h-64 rounded-full bg-brand-green blur-3xl" />
          <div className="absolute bottom-20 right-20 w-96 h-96 rounded-full bg-brand-teal blur-3xl" />
        </div>
        <div className="relative z-10 text-center px-12">
          <div className="w-24 h-24 rounded-2xl bg-brand-green/20 flex items-center justify-center mx-auto mb-8 border border-brand-green/30">
            <span className="text-brand-green font-bold text-4xl">D</span>
          </div>
          <h1 className="text-5xl font-bold text-white mb-4">D-ARCA</h1>
          <p className="text-xl text-brand-teal mb-2">Asset Risk & Cloud Analysis</p>
          <p className="text-brand-gray-400 max-w-md mx-auto mt-6">
            Cloud & SaaS Security Posture Management Platform.
            Monitor, analyze, and secure your cloud infrastructure and SaaS applications.
          </p>
          <div className="flex items-center justify-center gap-8 mt-12">
            <div className="text-center">
              <p className="text-3xl font-bold text-brand-green">AWS</p>
              <p className="text-xs text-brand-gray-400 mt-1">Cloud</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-brand-blue">Azure</p>
              <p className="text-xs text-brand-gray-400 mt-1">Cloud</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-brand-teal">GCP</p>
              <p className="text-xs text-brand-gray-400 mt-1">Cloud</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-white">SaaS</p>
              <p className="text-xs text-brand-gray-400 mt-1">Security</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right panel - form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          <div className="lg:hidden mb-8 text-center">
            <h1 className="text-3xl font-bold text-brand-navy">D-ARCA</h1>
            <p className="text-brand-gray-400 text-sm">Asset Risk & Cloud Analysis</p>
          </div>

          <h2 className="text-2xl font-bold text-brand-navy mb-2">Welcome back</h2>
          <p className="text-brand-gray-400 mb-8">Sign in to your account to continue</p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">
                Email address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full px-4 py-2.5 border border-brand-gray-300 rounded-lg focus:ring-2 focus:ring-brand-green focus:border-brand-green outline-none transition-all"
                placeholder="you@company.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-brand-gray-700 mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                  className="w-full px-4 py-2.5 pr-11 border border-brand-gray-300 rounded-lg focus:ring-2 focus:ring-brand-green focus:border-brand-green outline-none transition-all"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-brand-gray-400 hover:text-brand-gray-700 transition-colors"
                >
                  {showPassword ? (
                    <EyeSlashIcon className="w-5 h-5" />
                  ) : (
                    <EyeIcon className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary py-3 text-center disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>

          <p className="text-center text-sm text-brand-gray-400 mt-6">
            Don&apos;t have an account?{' '}
            <Link href="/auth/sign-up" className="text-brand-green font-medium hover:underline">
              Create account
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
