import React, { useState } from 'react'
import { Activity, BookOpenCheck, Eye, FileUp, Layers3, LockKeyhole, ShieldCheck } from 'lucide-react'
import { Reveal } from './ui'

const FEATURES = [
  {
    title: 'Web access logs',
    category: 'Live connector',
    summary: 'Monitor selected requests from a connected web server.',
    detail: 'The optional collector reads access logs and sends allowed request metadata to Argus. It does not collect form contents, request bodies, cookies, or authorization headers.',
    icon: Activity,
    tone: 'gold',
  },
  {
    title: 'Layered detection',
    category: 'How it works',
    summary: 'Rules and models provide complementary signals.',
    detail: 'The web-log path combines request-pattern rules, client behavior over time, and a text model. The flow-analysis path uses a separate classifier ensemble and anomaly detection.',
    icon: Layers3,
    tone: 'blue',
  },
  {
    title: 'Flow CSV analysis',
    category: 'Upload',
    summary: 'Analyze network-flow data from a prepared CSV file.',
    detail: 'Flow analysis is available through dataset upload. This project does not include a live network-flow connector.',
    icon: FileUp,
    tone: 'green',
  },
  {
    title: 'Explainable alerts',
    category: 'For analysts',
    summary: 'Review risk, evidence, and why an event was flagged.',
    detail: 'Alerts can show the detection sources and evidence, plus a local explanation. Repeated findings may be grouped into one alert.',
    icon: Eye,
    tone: 'rose',
  },
  {
    title: 'Privacy controls',
    category: 'You decide',
    summary: 'Choose what a connected collector is allowed to send.',
    detail: 'The collector filters and redacts selected data before sending it. Argus applies the source policy again when events arrive, and a source key can be revoked.',
    icon: LockKeyhole,
    tone: 'blue',
  },
  {
    title: 'Honest coverage',
    category: 'Know the limits',
    summary: 'See what each source can and cannot detect.',
    detail: 'Web access logs expose URLs and request metadata, not request bodies. Other live sources such as endpoint, email, and SSH logs are not currently implemented.',
    icon: BookOpenCheck,
    tone: 'gold',
  },
  {
    title: 'Human-controlled response',
    category: 'No automatic blocking',
    summary: 'Review suggested mitigations without changing your systems.',
    detail: 'Applying a mitigation in Argus is a simulation: it records the choice and may update a simulated blocklist. It does not execute firewall, WAF, or host changes.',
    icon: ShieldCheck,
    tone: 'green',
  },
]

export default function LoginFeatureGrid() {
  const [activeFeature, setActiveFeature] = useState(null)

  return (
    <section className="auth-features" id="auth-features" aria-labelledby="auth-features-title">
      <div className="auth-features-inner">
        <Reveal className="auth-features-heading">
          <p className="auth-features-eyebrow">Explore the platform</p>
          <h2 id="auth-features-title">A clearer picture of your security signals</h2>
          <p>Choose a card to learn what Argus does—and where its limits are.</p>
        </Reveal>

        <div className="feature-grid">
          {FEATURES.map((feature, index) => {
            const Icon = feature.icon
            const isActive = activeFeature === index
            return (
              <Reveal
                key={feature.title}
                delay={index * 0.07}
                className={`feature-grid-cell feature-grid-cell-${index + 1}`}
              >
                <button
                  type="button"
                  className={`feature-card feature-card-${feature.tone}${isActive ? ' is-active' : ''}`}
                  aria-expanded={isActive}
                  onClick={() => setActiveFeature(isActive ? null : index)}
                >
                  <span className="feature-card-top">
                    <span className="feature-icon"><Icon size={19} strokeWidth={1.7} /></span>
                    <span className="feature-category">{feature.category}</span>
                    <span className="feature-expand" aria-hidden="true">{isActive ? '−' : '+'}</span>
                  </span>
                  <span className="feature-title">{feature.title}</span>
                  <span className="feature-summary">{feature.summary}</span>
                  <span className="feature-detail" aria-hidden={!isActive}>{feature.detail}</span>
                </button>
              </Reveal>
            )
          })}
        </div>
      </div>
    </section>
  )
}
