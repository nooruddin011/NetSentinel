import React from 'react'

function SignalArtwork() {
  return (
    <svg viewBox="0 0 220 94" aria-hidden="true">
      <path d="M7 72h206M7 48h206M7 24h206" />
      <path className="scatter-line" d="m8 63 23-8 20 4 22-24 19 18 21-7 19 12 23-27 20 12 22-20 15 5" />
      <circle className="scatter-point point-one" cx="92" cy="53" r="4" />
      <circle className="scatter-point point-two" cx="155" cy="58" r="4" />
      <circle className="scatter-point point-three" cx="197" cy="43" r="4" />
    </svg>
  )
}

function LayersArtwork() {
  return (
    <div className="scatter-layer-list" aria-hidden="true">
      <span><i className="layer-mark mark-rule" /> Signatures <b>Patterns</b></span>
      <span><i className="layer-mark mark-behavior" /> Behavior <b>Over time</b></span>
      <span><i className="layer-mark mark-model" /> Text model <b>Variants</b></span>
    </div>
  )
}

function EventArtwork() {
  return (
    <div className="scatter-event-body" aria-hidden="true">
      <span className="event-method">GET</span>
      <span className="event-route">/account/sign-in</span>
      <span className="event-status">Illustrative request</span>
      <span className="event-bars"><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /></span>
    </div>
  )
}

const SCATTER_CARDS = [
  { className: 'scatter-card-chart', label: 'Illustrative activity', content: <SignalArtwork /> },
  { className: 'scatter-card-layers', label: 'Multiple signals', content: <LayersArtwork /> },
  { className: 'scatter-card-event', label: 'Web log metadata', content: <EventArtwork /> },
]

export default function ImageScatter() {
  return (
    <div className="scatter-art" aria-hidden="true">
      <div className="scatter-glow" />
      {SCATTER_CARDS.map((card, index) => (
        <figure
          className={`scatter-card ${card.className}`}
          key={card.className}
          style={{ '--scatter-delay': `${index * 120}ms` }}
        >
          <figcaption><span className="scatter-status" />{card.label}</figcaption>
          {card.content}
        </figure>
      ))}
      <div className="scatter-orbit scatter-orbit-one" />
      <div className="scatter-orbit scatter-orbit-two" />
    </div>
  )
}
