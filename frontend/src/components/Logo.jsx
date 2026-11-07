import React from 'react'

// Shield + eye: "Argus", the all-seeing watchman.
export default function Logo({ size = 32 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-label="Argus logo">
      <defs>
        <linearGradient id="argusGrad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#efdcab" />
          <stop offset="1" stopColor="#b98a3e" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 4.5 6.8v8.2c0 7.2 4.7 12.6 11.5 14.5 6.8-1.9 11.5-7.3 11.5-14.5V6.8L16 2.5z" fill="url(#argusGrad)" />
      <path d="M7.5 15.5C10 11.8 12.8 10 16 10s6 1.8 8.5 5.5C22 19.2 19.2 21 16 21s-6-1.8-8.5-5.5z" fill="#0e1110" opacity="0.92" />
      <circle cx="16" cy="15.5" r="3.4" fill="url(#argusGrad)" />
      <circle cx="16" cy="15.5" r="1.4" fill="#0e1110" />
    </svg>
  )
}
