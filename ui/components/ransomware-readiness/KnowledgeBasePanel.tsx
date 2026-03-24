'use client'

import { useEffect, useRef } from 'react'
import {
  XMarkIcon,
  BookOpenIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  AcademicCapIcon,
  LinkIcon,
  ServerStackIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline'

interface KnowledgeBasePanelProps {
  open: boolean
  onClose: () => void
}

const DOMAINS = [
  {
    id: 'D1',
    name: 'Identity & Access',
    nist: 'PR.AC / PR.AA',
    description:
      'Controls MFA enforcement, least-privilege IAM policies, dormant credential hygiene, and federation security. Compromised identities are the #1 initial access vector for ransomware in cloud environments.',
  },
  {
    id: 'D2',
    name: 'Protection & Encryption',
    nist: 'PR.DS',
    description:
      'Validates encryption at rest and in transit, KMS key rotation, and data-classification tagging. Strong encryption limits the blast radius if an attacker gains access to storage resources.',
  },
  {
    id: 'D3',
    name: 'Backup & Recovery',
    nist: 'PR.IP / RC.RP',
    description:
      'Measures immutable backup coverage, cross-region/cross-account replication, retention policies, and recovery point freshness. This domain is the last line of defense — if backups survive, recovery is possible.',
  },
  {
    id: 'D4',
    name: 'Network Security',
    nist: 'PR.AC / PR.PT',
    description:
      'Assesses network segmentation, security-group hygiene, WAF deployment, and public exposure surface. Lateral movement through flat networks is a hallmark of modern ransomware campaigns.',
  },
  {
    id: 'D5',
    name: 'System Hardening',
    nist: 'PR.IP / PR.PT',
    description:
      'Checks patch management, image hardening, secrets management, and runtime protection. Unpatched workloads and exposed secrets provide easy footholds for ransomware operators.',
  },
  {
    id: 'D6',
    name: 'Logging & Detection',
    nist: 'DE.CM / DE.AE',
    description:
      'Validates CloudTrail/audit-log coverage, anomaly detection, SIEM integration, and alert routing. Early detection is the difference between a contained incident and a full-scale breach.',
  },
  {
    id: 'D7',
    name: 'Governance & Response',
    nist: 'GV / RS.RP',
    description:
      'Evaluates incident-response plans, tabletop exercises, communication playbooks, and executive accountability. Organizations with tested response plans recover 4× faster on average.',
  },
]

const RISKS = [
  {
    title: 'Data exfiltration before encryption',
    description:
      'Modern ransomware groups (double-extortion) steal data before encrypting it, threatening public release even if backups are intact.',
  },
  {
    title: 'Credential compromise & lateral movement',
    description:
      'Attackers harvest cloud IAM keys and session tokens to pivot across accounts and services, escalating privileges silently.',
  },
  {
    title: 'Backup destruction',
    description:
      'Sophisticated operators target backup systems first — deleting snapshots, disabling versioning, and removing cross-region replicas before deploying ransomware.',
  },
  {
    title: 'Supply-chain entry points',
    description:
      'Third-party integrations, CI/CD pipelines, and shared AMIs/container images can serve as initial access vectors if not hardened.',
  },
  {
    title: 'Cloud-native misconfigurations',
    description:
      'Public S3 buckets, overly permissive IAM roles, disabled logging, and unencrypted volumes create opportunities that do not exist in traditional on-premise environments.',
  },
]

const REFERENCES = [
  {
    title: 'NIST Cybersecurity Framework (CSF) 2.0',
    url: 'https://www.nist.gov/cyberframework',
    description: 'The foundation for our domain mapping and control taxonomy.',
  },
  {
    title: 'NISTIR 8374 — Ransomware Risk Management',
    url: 'https://csrc.nist.gov/publications/detail/nistir/8374/final',
    description:
      'Specific ransomware guidance mapped to CSF functions: Identify, Protect, Detect, Respond, Recover.',
  },
  {
    title: 'CISA #StopRansomware Guide',
    url: 'https://www.cisa.gov/stopransomware',
    description:
      'US government best-practices guide with ransomware-specific hardening checklists and response playbooks.',
  },
  {
    title: 'MITRE ATT&CK — Enterprise Cloud Matrix',
    url: 'https://attack.mitre.org/matrices/enterprise/cloud/',
    description:
      'Adversarial tactics, techniques, and procedures (TTPs) observed in real-world cloud ransomware incidents.',
  },
  {
    title: 'CSA Cloud Controls Matrix (CCM) v4',
    url: 'https://cloudsecurityalliance.org/research/cloud-controls-matrix',
    description:
      'Cloud-specific security controls framework that complements NIST CSF for multi-cloud environments.',
  },
  {
    title: 'Verizon DBIR — Ransomware Section',
    url: 'https://www.verizon.com/business/resources/reports/dbir/',
    description:
      'Annual data-driven analysis of ransomware trends, attack vectors, and time-to-compromise statistics.',
  },
  {
    title: 'ENISA Threat Landscape for Ransomware Attacks',
    url: 'https://www.enisa.europa.eu/publications/enisa-threat-landscape-for-ransomware-attacks',
    description:
      'European analysis of ransomware lifecycle, business models, and recommended countermeasures.',
  },
  {
    title: 'AWS Security Best Practices — Ransomware',
    url: 'https://docs.aws.amazon.com/prescriptive-guidance/latest/ransomware-mitigation/',
    description:
      'Provider-specific guidance for protecting AWS workloads against ransomware campaigns.',
  },
]

const SCORING_METHODOLOGY = [
  { label: 'Check weight', description: 'Each rule carries a severity-based weight (Critical=10, High=7, Medium=4, Low=1).' },
  { label: 'Domain score', description: 'Weighted average of passed checks within the domain, normalized to 0–100.' },
  { label: 'Global score', description: 'Weighted average of all 7 domain scores. Domain weights reflect ransomware impact (e.g., Backup & Recovery carries higher weight).' },
  { label: 'Maturity levels', description: 'Excelente (≥90), Bueno (70–89), Moderado (50–69), Bajo (30–49), Crítico (<30).' },
]

export default function KnowledgeBasePanel({ open, onClose }: KnowledgeBasePanelProps) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleEscape(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    if (open) {
      document.addEventListener('keydown', handleEscape)
      document.body.style.overflow = 'hidden'
    }
    return () => {
      document.removeEventListener('keydown', handleEscape)
      document.body.style.overflow = ''
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" />

      {/* Panel */}
      <div
        ref={panelRef}
        onClick={(e) => e.stopPropagation()}
        className="relative w-full max-w-2xl bg-white shadow-2xl animate-slide-in-right overflow-y-auto scrollbar-thin"
      >
        {/* Header */}
        <div className="sticky top-0 z-10 bg-brand-navy text-white px-6 py-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <BookOpenIcon className="w-6 h-6" />
              <div>
                <h2 className="text-lg font-bold">Ransomware Readiness — Knowledge Base</h2>
                <p className="text-sm text-white/70 mt-0.5">Methodology, risks & references</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-white/10 transition-colors"
              aria-label="Close panel"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="px-6 py-6 space-y-8">
          {/* What is RR */}
          <section>
            <SectionHeading icon={<ShieldCheckIcon className="w-5 h-5" />} title="What is Ransomware Readiness?" />
            <div className="prose-sm text-brand-gray-600 space-y-3 mt-3">
              <p>
                <strong>Ransomware Readiness</strong> measures how prepared your cloud environment is to
                <em> prevent, detect, withstand, and recover from</em> a ransomware attack. Unlike traditional
                vulnerability scanning, it evaluates organizational and architectural resilience across the full
                attack lifecycle.
              </p>
              <p>
                Our assessment is built on the <strong>NIST Cybersecurity Framework (CSF) 2.0</strong> and
                the <strong>NISTIR 8374 — Ransomware Risk Management</strong> profile, adapted for multi-cloud
                environments (AWS, Azure, GCP). It covers <strong>7 security domains</strong> mapped to the
                5 NIST functions: <em>Govern, Identify, Protect, Detect, and Respond/Recover</em>.
              </p>
              <p>
                Each assessment runs automated checks against your cloud accounts, evaluates governance
                inputs provided by your team, and produces an actionable score with prioritized remediation
                guidance.
              </p>
            </div>
          </section>

          {/* Scoring methodology */}
          <section>
            <SectionHeading icon={<ChartBarIcon className="w-5 h-5" />} title="Scoring Methodology" />
            <div className="mt-3 space-y-2">
              {SCORING_METHODOLOGY.map((item) => (
                <div key={item.label} className="flex gap-3 items-start">
                  <span className="mt-1 w-2 h-2 rounded-full bg-brand-green shrink-0" />
                  <p className="text-sm text-brand-gray-600">
                    <strong className="text-brand-navy">{item.label}:</strong> {item.description}
                  </p>
                </div>
              ))}
            </div>
          </section>

          {/* 7 Domains */}
          <section>
            <SectionHeading icon={<ServerStackIcon className="w-5 h-5" />} title="The 7 Domains" />
            <div className="mt-3 space-y-3">
              {DOMAINS.map((d) => (
                <details key={d.id} className="group border border-brand-gray-200 rounded-lg">
                  <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none hover:bg-brand-gray-50 rounded-lg transition-colors">
                    <span className="text-xs font-bold text-white bg-brand-navy rounded px-2 py-0.5">{d.id}</span>
                    <span className="text-sm font-semibold text-brand-navy flex-1">{d.name}</span>
                    <span className="text-xs text-brand-gray-400 font-mono">{d.nist}</span>
                    <svg className="w-4 h-4 text-brand-gray-400 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                  </summary>
                  <div className="px-4 pb-3 text-sm text-brand-gray-600 leading-relaxed border-t border-brand-gray-100 pt-3">
                    {d.description}
                  </div>
                </details>
              ))}
            </div>
          </section>

          {/* Key risks */}
          <section>
            <SectionHeading icon={<ExclamationTriangleIcon className="w-5 h-5" />} title="Key Cloud Ransomware Risks" />
            <div className="mt-3 space-y-3">
              {RISKS.map((r, i) => (
                <div key={i} className="bg-red-50/50 border border-red-100 rounded-lg p-4">
                  <p className="text-sm font-semibold text-red-800">{r.title}</p>
                  <p className="text-sm text-red-700/80 mt-1">{r.description}</p>
                </div>
              ))}
            </div>
          </section>

          {/* References & literature */}
          <section>
            <SectionHeading icon={<AcademicCapIcon className="w-5 h-5" />} title="References & Literature" />
            <div className="mt-3 space-y-3">
              {REFERENCES.map((ref, i) => (
                <a
                  key={i}
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block border border-brand-gray-200 rounded-lg p-4 hover:bg-brand-gray-50 hover:border-brand-blue/30 transition-colors group"
                >
                  <div className="flex items-start gap-3">
                    <LinkIcon className="w-4 h-4 text-brand-blue mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-semibold text-brand-navy group-hover:text-brand-blue transition-colors">
                        {ref.title}
                      </p>
                      <p className="text-xs text-brand-gray-500 mt-1">{ref.description}</p>
                    </div>
                  </div>
                </a>
              ))}
            </div>
          </section>

          {/* Methodology note */}
          <section className="bg-brand-navy/5 border border-brand-navy/10 rounded-xl p-5">
            <p className="text-xs text-brand-gray-500 leading-relaxed">
              <strong className="text-brand-navy">Methodology note:</strong> This assessment engine continuously
              evaluates your cloud accounts using automated API-based checks combined with manual governance
              inputs. Rules are weighted by ransomware-specific impact, and domain weights reflect the
              NISTIR 8374 ransomware profile priorities. The scoring model is updated as new threat intelligence
              and NIST guidance become available.
            </p>
          </section>
        </div>
      </div>
    </div>
  )
}

function SectionHeading({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="text-brand-navy">{icon}</span>
      <h3 className="text-base font-bold text-brand-navy">{title}</h3>
    </div>
  )
}
