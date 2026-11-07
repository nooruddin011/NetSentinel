import React from 'react'

// A crash inside one page must not blank the whole console.
export default class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null } }
  static getDerivedStateFromError(error) { return { error } }
  componentDidCatch(error, info) { console.error('UI error:', error, info) }
  componentDidUpdate(prev) { if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null }) }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="note error" role="alert" style={{ margin: '2rem auto', maxWidth: 560 }}>
        <strong>Something went wrong on this page.</strong>
        <div className="muted" style={{ fontSize: '.85rem', margin: '.4rem 0' }}>{String(this.state.error.message || this.state.error)}</div>
        <button className="btn sm" onClick={() => this.setState({ error: null })}>Try again</button>
      </div>
    )
  }
}
