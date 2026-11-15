import React, { useEffect, useRef } from 'react'

let gisPromise
let initializedClientId
let activeCredentialCallback

function credentialCallback(response) {
  activeCredentialCallback?.(response)
}

function loadGoogleIdentity() {
  if (window.google?.accounts?.id) return Promise.resolve(window.google.accounts.id)
  if (!gisPromise) {
    gisPromise = new Promise((resolve, reject) => {
      let script = document.getElementById('google-identity-services')
      const created = !script
      if (created) {
        script = document.createElement('script')
        script.id = 'google-identity-services'
        script.src = 'https://accounts.google.com/gsi/client'
        script.async = true
        script.defer = true
      }
      script.addEventListener('load', () => window.google?.accounts?.id ? resolve(window.google.accounts.id) : reject(new Error('Google sign-in could not initialize.')), { once: true })
      script.addEventListener('error', () => reject(new Error('Could not load Google sign-in. Check your connection and try again.')), { once: true })
      if (window.google?.accounts?.id) resolve(window.google.accounts.id)
      if (created) document.head.appendChild(script)
    }).catch((error) => { gisPromise = null; throw error })
  }
  return gisPromise
}

export default function GoogleSignInButton({ clientId, mode = 'signin', theme = 'light', onCredential, onError }) {
  const host = useRef(null)
  const callbacks = useRef({ onCredential, onError })
  callbacks.current = { onCredential, onError }

  useEffect(() => {
    let cancelled = false
    loadGoogleIdentity().then((identity) => {
      if (cancelled || !host.current) return
      activeCredentialCallback = (response) => {
        if (response?.credential) callbacks.current.onCredential?.(response.credential)
        else callbacks.current.onError?.(new Error('Google did not return a sign-in credential.'))
      }
      if (initializedClientId !== clientId) {
        identity.initialize({
          client_id: clientId,
          ux_mode: 'popup',
          auto_select: false,
          callback: credentialCallback,
        })
        initializedClientId = clientId
      }
      host.current.replaceChildren()
      identity.renderButton(host.current, {
        type: 'standard',
        theme: theme === 'dark' ? 'filled_black' : 'outline',
        size: 'large',
        text: mode === 'signup' ? 'signup_with' : 'signin_with',
        shape: 'pill',
        logo_alignment: 'left',
        width: Math.min(360, Math.max(220, Math.floor(host.current.getBoundingClientRect().width || 320))),
      })
    }).catch((error) => { if (!cancelled) callbacks.current.onError?.(error) })
    return () => {
      cancelled = true
      host.current?.replaceChildren()
      activeCredentialCallback = null
    }
  }, [clientId, mode, theme])

  return <div className="google-signin-slot" ref={host} aria-label={mode === 'signup' ? 'Sign up with Google' : 'Sign in with Google'} />
}
