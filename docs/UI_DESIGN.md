# UI design system: "Obsidian & Brass"

A calm, distinctive console rather than a generic blue-and-purple dashboard.

## Principles
* **One accent, used sparingly.** Brass marks what to do next (primary buttons, the active page, eyebrow labels). Ice-blue is the secondary data colour. Severity keeps its own semantic colours (red, orange, yellow, light blue) so risk is never ambiguous.
* **Warm neutrals, not navy.** Dark theme ("Obsidian") is graphite-green with bone-white text; the light theme ("Paper") is warm paper with ink-black pill buttons. Both are driven by the same CSS variables (`frontend/src/index.css`).
* **Depth from light and hairlines.** A soft, off-centre glow and 1 px borders instead of heavy shadows or gradients.
* **Big, tight typography.** Inter Tight (UI) and JetBrains Mono (IPs, payloads), bundled with the app (no third-party font requests). Display titles use tight tracking; small uppercase "eyebrow" labels give hierarchy.
* **Motion with a purpose.** Content fades up as it scrolls into view (staggered), pages transition in, headline numbers count up, buttons lift on hover and press on click. Everything is disabled for users who prefer reduced motion.

## Tokens
| Token | Dark | Light |
|---|---|---|
| Background / panel | `#0e1110` / `#161b19` | `#f1ede4` / `#fbf8f2` |
| Text / muted | `#ece8df` / `#98a29c` | `#1d1c18` / `#6b675d` |
| Accent (brass) | `#d6a95a` | `#9a6f1f` |
| Secondary (ice) | `#bcd6e3` | `#41667a` |
| Primary button | brass on dark ink | ink on bone |
| Critical / High / Medium / Low | `#ef6a6a` `#f2994a` `#e6c35c` `#8fbbd6` | `#b3261e` `#b4540f` `#8a6a0a` `#2b6a92` |

Charts take their colours from `theme.jsx` (`useChart()`), never from hard-coded hex values, so both themes stay consistent.

## Building blocks (`components/ui.jsx`)
`PageHead` (eyebrow, title, subtitle, actions) · `Card` and `Stat` (scroll-reveal, count-up) · `Reveal` · `Modal` · `ScopeSwitch` · `Spinner` (shimmer skeleton) · severity/status/role badges.

## Accessibility
Visible focus rings, keyboard-closable dialogs (Esc), labelled icon buttons, `prefers-reduced-motion` respected, status never conveyed by colour alone (badges carry text).
