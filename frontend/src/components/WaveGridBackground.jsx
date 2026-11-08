import { useEffect, useRef } from 'react'

function readHex(value) {
  const match = value.replace('#', '').match(/^([\da-f]{3}|[\da-f]{6})$/i)
  if (!match) return [160, 160, 160]
  const hex = match[1].length === 3 ? [...match[1]].map((char) => char + char).join('') : match[1]
  return [0, 2, 4].map((index) => parseInt(hex.slice(index, index + 2), 16))
}

function mixColor(first, second, amount) {
  return first.map((channel, index) => Math.round(channel + (second[index] - channel) * amount))
}

function rgba(color, alpha) {
  return `rgba(${color[0]},${color[1]},${color[2]},${alpha})`
}

export default function WaveGridBackground({ colorBase, colorHigh, className = '' }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const context = canvas?.getContext('2d', { alpha: true })
    if (!canvas || !context) return undefined

    const baseColor = readHex(colorBase)
    const peakColor = readHex(colorHigh)
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)')
    const waves = []
    const columns = window.innerWidth < 640 ? 25 : 34
    const rows = window.innerWidth < 640 ? 18 : 23
    let width = 1
    let height = 1
    let pixelRatio = 1
    let animationId = 0
    let lastFrame = 0
    let lastPointerAt = 0
    let autoWaveAt = 0
    let lastPointer = null

    const resize = () => {
      width = window.innerWidth
      height = window.innerHeight
      pixelRatio = Math.min(window.devicePixelRatio || 1, 1.35)
      canvas.width = Math.round(width * pixelRatio)
      canvas.height = Math.round(height * pixelRatio)
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0)
      draw(performance.now())
    }

    const addWave = (x, y, strength = 1) => {
      waves.push({ x, y, born: performance.now(), strength })
      if (waves.length > 18) waves.shift()
    }

    const onPointerMove = (event) => {
      const point = { x: event.clientX, y: event.clientY }
      if (!lastPointer || Math.hypot(point.x - lastPointer.x, point.y - lastPointer.y) > 34) {
        addWave(point.x, point.y, .75)
        lastPointer = point
        lastPointerAt = performance.now()
      }
    }

    const onPointerLeave = () => { lastPointer = null }

    function draw(now) {
      context.clearRect(0, 0, width, height)
      const points = Array.from({ length: rows + 1 }, (_, row) => {
        const vertical = row / rows
        const y = height * (.12 + Math.pow(vertical, 1.2) * .76)
        return Array.from({ length: columns + 1 }, (_, column) => {
          const x = width * (.035 + (column / columns) * .93)
          let lift = 0
          for (const wave of waves) {
            const age = (now - wave.born) / 1000
            const distance = Math.hypot(x - wave.x, (y - wave.y) * 1.12)
            const ring = distance - age * 330
            const envelope = Math.exp(-(ring * ring) / 5200) * Math.exp(-age / 2.1)
            lift += Math.cos(ring * .047) * envelope * wave.strength * 17
          }
          return { x, y: y - lift, lift }
        })
      })

      for (let row = 0; row < rows; row++) {
        for (let column = 0; column < columns; column++) {
          const a = points[row][column]
          const b = points[row][column + 1]
          const c = points[row + 1][column + 1]
          const d = points[row + 1][column]
          const peak = Math.min(1, Math.max(0, (a.lift + b.lift + c.lift + d.lift) / 46))
          const color = mixColor(baseColor, peakColor, peak)
          context.beginPath()
          context.moveTo(a.x, a.y)
          context.lineTo(b.x, b.y)
          context.lineTo(c.x, c.y)
          context.lineTo(d.x, d.y)
          context.closePath()
          context.fillStyle = rgba(color, .012 + peak * .075)
          context.fill()
          context.strokeStyle = rgba(peakColor, .09 + peak * .23)
          context.lineWidth = .65 + peak * .35
          context.stroke()
        }
      }
    }

    const animate = (now) => {
      lastFrame = now
      waves.splice(0, waves.length, ...waves.filter((wave) => (now - wave.born) / 1000 < 5.5))
      if (now - lastPointerAt > 3200 && now - autoWaveAt > 2500) {
        addWave(width * (.2 + Math.random() * .6), height * (.28 + Math.random() * .5), .55)
        autoWaveAt = now
      }
      draw(now)
      animationId = requestAnimationFrame(animate)
    }

    resize()
    window.addEventListener('resize', resize)
    if (!reducedMotion.matches) {
      window.addEventListener('pointermove', onPointerMove, { passive: true })
      window.addEventListener('pointerleave', onPointerLeave)
      animationId = requestAnimationFrame(animate)
    }
    const onMotionPreferenceChange = (event) => {
      cancelAnimationFrame(animationId)
      if (event.matches) {
        window.removeEventListener('pointermove', onPointerMove)
        window.removeEventListener('pointerleave', onPointerLeave)
        waves.length = 0
        draw(performance.now())
      } else {
        window.addEventListener('pointermove', onPointerMove, { passive: true })
        window.addEventListener('pointerleave', onPointerLeave)
        lastFrame = 0
        animationId = requestAnimationFrame(animate)
      }
    }
    reducedMotion.addEventListener?.('change', onMotionPreferenceChange)

    return () => {
      cancelAnimationFrame(animationId)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', onPointerMove)
      window.removeEventListener('pointerleave', onPointerLeave)
      reducedMotion.removeEventListener?.('change', onMotionPreferenceChange)
    }
  }, [colorBase, colorHigh])

  return <div className={`wave-grid-canvas ${className}`} aria-hidden="true"><canvas ref={canvasRef} /></div>
}
