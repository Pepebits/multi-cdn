---
name: Multi-CDN Control Panel (TapBits Neo-Brutalist)
colors:
  surface: '#fcf9f8'
  surface-dim: '#dcd9d8'
  surface-bright: '#fcf9f8'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f6f3f2'
  surface-container: '#f0edec'
  surface-container-high: '#eae7e7'
  surface-container-highest: '#e4e2e1'
  on-surface: '#1b1c1b'
  on-surface-variant: '#4d4632'
  inverse-surface: '#303030'
  inverse-on-surface: '#f3f0ef'
  outline: '#7f775f'
  outline-variant: '#d0c6ab'
  surface-tint: '#705d00'
  primary: '#705d00'
  on-primary: '#ffffff'
  primary-container: '#fdd400'
  on-primary-container: '#6f5c00'
  inverse-primary: '#eac400'
  secondary: '#605e5e'
  on-secondary: '#ffffff'
  secondary-container: '#e6e1e1'
  on-secondary-container: '#666464'
  tertiary: '#006a65'
  on-tertiary: '#ffffff'
  tertiary-container: '#57ede4'
  on-tertiary-container: '#006964'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#ffe171'
  primary-fixed-dim: '#eac400'
  on-primary-fixed: '#221b00'
  on-primary-fixed-variant: '#554600'
  secondary-fixed: '#e6e1e1'
  secondary-fixed-dim: '#c9c6c5'
  on-secondary-fixed: '#1c1b1b'
  on-secondary-fixed-variant: '#484646'
  tertiary-fixed: '#65f8ef'
  tertiary-fixed-dim: '#40dbd3'
  on-tertiary-fixed: '#00201e'
  on-tertiary-fixed-variant: '#00504c'
  background: '#fcf9f8'
  on-background: '#1b1c1b'
  surface-variant: '#e4e2e1'
typography:
  display-lg:
    fontFamily: Hanken Grotesk
    fontSize: 44px
    fontWeight: '900'
    lineHeight: 52px
    letterSpacing: -0.03em
  display-lg-mobile:
    fontFamily: Hanken Grotesk
    fontSize: 36px
    fontWeight: '900'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Hanken Grotesk
    fontSize: 32px
    fontWeight: '800'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Hanken Grotesk
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Hanken Grotesk
    fontSize: 20px
    fontWeight: '700'
    lineHeight: 28px
    letterSpacing: 0em
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '500'
    lineHeight: 24px
    letterSpacing: 0em
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0.01em
  label-mono-lg:
    fontFamily: JetBrains Mono
    fontSize: 18px
    fontWeight: '700'
    lineHeight: 24px
    letterSpacing: -0.01em
  label-mono-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 18px
    letterSpacing: 0.02em
  label-mono-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.05em
  label-action:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '600'
    lineHeight: 20px
    letterSpacing: 0.01em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-tablet: 1.5rem
  margin: 1rem
  margin-tablet: 2rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
---

## Brand & Style

Internal operations panel for a multi-CDN failover controller (Cloudflare primary, Gcore backup). It reuses the TapBits neo-brutalist visual language: bone canvas, 2px ink borders, hard zero-blur offset shadows, yellow primary actions, teal confirmations, square red status dots. The panel must be readable at a glance during a live football match, when Spanish ISPs block Cloudflare IPs, on desktop and on a phone.

Tone: assertive, mechanical, trustworthy. No gradients, no glassmorphism, no soft shadows. Interface language: Spanish.

## Colors (semantic mapping for this panel)

- **Bone `#fcf9f8`**: page canvas. **White** for cards.
- **Ink `#1c1b1b`**: text, top bar, 2px borders, hard shadows.
- **Teal `#00c2ba`** = NORMAL: domain served by Cloudflare, checks OK, certificate valid. Text on teal is Ink.
- **Yellow `#fdd400`** = BACKUP ACTIVE / primary actions: domain served by Gcore, "Cambiar a Gcore" button, active match window. Text on yellow is Ink.
- **Primary Red `#bb0018`** = BLOCKED / ERROR: IP blocked by ISPs, failed switch, origin down, expiring certificate. Used for status pills and destructive buttons, never body text.
- **Electric Red `#ff3e3e`**: only the 8x8 square "live" dot next to real-time data (feed freshness, live match).
- **Ink-grey `#605e5e` on `#e6e1e1`** = MANUAL / MAINTENANCE: automation paused.

Every status is shown with color + text label + icon, never color alone.

## Typography

- **Hanken Grotesk 700-900**: page titles, domain names on cards.
- **Inter 400-600**: UI text, tables, forms, explanations.
- **JetBrains Mono 600-700**: IPs, hostnames, timestamps, counters, DNS records, ISP status readouts (e.g. `[ 3 / 5 ISP BLOQUEADO ]`, `TTL 60`, `20:46 UTC`).

## Layout

- Desktop: left sidebar (Resumen, Dominios, Proveedores, Servidor, Calendario, Historial, Ajustes) in Ink with bone text; content area with 32px margins, 12-column grid, 24px gutters.
- Mobile: top app bar in Ink + bottom navigation; single-column cards; 16px margins; touch targets >= 48px.
- Strict 4/8px spacing rhythm.

## Elevation & Shapes

- Cards: white, `2px solid #1c1b1b`, `box-shadow: 3px 3px 0 #1c1b1b`, radius 8px.
- Buttons and modals: `4px 4px 0 #1c1b1b`; pressed state translates +3px,+3px and removes the shadow.
- Chips/pills: 4px radius, 2px ink border, `2px 2px 0` shadow.
- Status dot: 8x8 square, 0 radius.

## Components

- **Domain status card**: domain name (Hanken), priority tag (CRÍTICA / MEDIA / BAJA), big status pill (CLOUDFLARE / GCORE / BLOQUEADO / MANUAL), active CDN, last change (mono timestamp + reason), mini grid of 5 ISPs (Movistar, Vodafone, Orange, Digi, MásMóvil) each as a small square tile teal (libre) or red (bloqueado), and action buttons.
- **ISP matrix**: table rows = Cloudflare IPs of the domain (mono), columns = 5 ISPs, cells teal/red with mono label.
- **Switch confirmation modal**: bone background, 6px hard shadow, explains the DNS change (before -> after in mono), requires typing the domain name to confirm.
- **Audit timeline**: vertical list, each entry with mono timestamp, actor (AUTO / usuario), signals that triggered it, DNS diff.
- **Match banner**: full-width yellow banner when a match window is active, with red live dot and countdown in mono.
- **Primary button** yellow; **secondary** white; **confirm/healthy** teal; **destructive** white with red border.
