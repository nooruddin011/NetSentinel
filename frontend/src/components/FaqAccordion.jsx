import React, { useState } from 'react'

const FAQ_ITEMS = [
  {
    question: 'What is Argus?',
    answer: 'Argus is a threat-monitoring dashboard that combines detection rules and machine-learning models to analyze events, create alerts, and explain why activity was flagged.',
  },
  {
    question: 'What data can Argus monitor?',
    answer: 'It can monitor web-server access logs in real time through its optional collector. It can also analyze uploaded network-flow CSV files. Other live source types, such as endpoint and email logs, are not currently available.',
  },
  {
    question: 'Can Argus see the information I submit in a web form?',
    answer: 'No. The web-log collector sends request metadata such as the URL, method, status, and user agent. It does not read form contents, request bodies, cookies, or authorization headers, so attacks contained only in a request body are not visible through this connector.',
  },
  {
    question: 'Why might the dashboard show simulated activity?',
    answer: 'When no healthy live source is connected, the dashboard can show generated demo traffic. It is labeled as demo data and is not activity observed from your systems. In Auto mode, the simulator switches off when a healthy live source connects.',
  },
  {
    question: 'Does Argus automatically block attacks?',
    answer: 'No. Mitigation actions are simulations: Argus can record the action and generate example rule text, but it does not apply firewall, WAF, or host changes.',
  },
  {
    question: 'How should I interpret the detection metrics?',
    answer: 'The published model metrics are based on generated datasets and do not establish how accurately Argus will detect threats in a real environment. Validate it with appropriate labeled data and your own monitoring before relying on it operationally.',
  },
  {
    question: 'Who can create an account?',
    answer: 'If self-registration is enabled, new accounts start with read-only Viewer access. An Admin can change a user’s role or turn registration off. If registration is disabled, an Admin must create your account.',
  },
]

export default function FaqAccordion({ items = FAQ_ITEMS, title = 'Frequently asked questions' }) {
  const [activeIndex, setActiveIndex] = useState(null)

  return (
    <section className="auth-faq" id="auth-faq" aria-labelledby="auth-faq-title">
      <div className="auth-faq-inner">
        <p className="auth-faq-eyebrow">Good to know</p>
        <h2 id="auth-faq-title">{title}</h2>
        <p className="auth-faq-intro">Clear answers about Argus, its data sources, and its limitations.</p>
        <ul className="faq-list">
          {items.map((item, index) => {
            const isActive = activeIndex === index
            const buttonId = `auth-faq-question-${index}`
            const panelId = `auth-faq-answer-${index}`
            return (
              <li className={`faq-item${isActive ? ' is-open' : ''}`} key={item.question}>
                <button
                  className="faq-question"
                  id={buttonId}
                  type="button"
                  aria-expanded={isActive}
                  aria-controls={panelId}
                  onClick={() => setActiveIndex(isActive ? null : index)}
                >
                  <span>{item.question}</span>
                  <span className="faq-toggle" aria-hidden="true">{isActive ? '−' : '+'}</span>
                </button>
                <div
                  className="faq-answer"
                  id={panelId}
                  role="region"
                  aria-labelledby={buttonId}
                  aria-hidden={!isActive}
                >
                  <div className="faq-answer-inner"><p>{item.answer}</p></div>
                </div>
              </li>
            )
          })}
        </ul>
      </div>
    </section>
  )
}
