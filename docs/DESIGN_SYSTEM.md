# Fishnet — Frontend Design System & Page Specifications

> **PURPOSE**: This is the single design reference for the Fishnet dashboard.
> Feed this entire file to Claude Code alongside your task prompt.
> It contains every color, font, spacing value, component spec, and
> page-by-page wireframe your frontend dev needs to produce pixel-accurate UI.

> **Tech Stack**: React 19 + Vite + Tailwind CSS v4 + Lucide React icons + React Router DOM
> **Fonts**: Inter (Google Fonts, weights 400/500/600/700) + JetBrains Mono (400/500)

---

## 1. BRAND IDENTITY

- **Product**: Fishnet — local-first cryptographic security proxy for AI agents
- **Personality**: Precise. Trustworthy. Technical. Minimal.
- **Mood**: "Security control room" — dark, focused, calm authority
- **NOT**: Consumer SaaS, playful, colorful, bubbly

---

## 2. COLOR SYSTEM

### 2.1 Brand Colors
```
Brand Primary:      #E63946   — CTAs, active nav, accent, logo mark
Brand Hover:        #CC2D3B   — Hover state on brand buttons
Brand Muted:        rgba(230,57,70,0.12) — Active nav background, subtle brand tints
```

### 2.2 Dark Theme (Dashboard — DEFAULT)
```
Background Root:    #0A0A0B   — Page background, outermost layer
Surface:            #111113   — Cards, sidebar, panels
Surface Raised:     #1A1A1D   — Dropdowns, modals, elevated cards
Surface Hover:      #222225   — Hover state on surface elements
Surface Input:      #161618   — Input field backgrounds

Border Default:     #2A2A2E   — Card borders, dividers
Border Subtle:      #1F1F23   — Very faint separators inside cards
Border Focus:       #E63946   — Focus ring color

Text Primary:       #F5F5F7   — Headings, main content
Text Secondary:     #A1A1AA   — Descriptions, secondary labels
Text Tertiary:      #71717A   — Placeholders, timestamps, disabled
Text Inverse:       #0A0A0B   — Text on brand-colored buttons
```

### 2.3 Light Theme (Login/Signup page ONLY)
```
Background:         #FAFAFA   — Page background
Surface:            #FFFFFF   — Form card
Surface Raised:     #F5F5F5   — CLI hint box
Border:             #E4E4E7   — Input borders, dividers

Text Primary:       #18181B   — Headings, input text
Text Secondary:     #52525B   — Body text
Text Tertiary:      #A1A1AA   — Placeholders
```

### 2.4 Semantic / Status Colors
```
Success:            #22C55E   — Approved, running, healthy
Success Muted BG:   rgba(34,197,94,0.12)
Warning:            #F59E0B   — Budget threshold, caution
Warning Muted BG:   rgba(245,158,11,0.12)
Danger:             #EF4444   — Denied, blocked, errors, stopped
Danger Muted BG:    rgba(239,68,68,0.12)
Info:               #3B82F6   — Informational, links
Info Muted BG:      rgba(59,130,246,0.12)
```

### 2.5 Service Indicator Colors (small dots/badges next to service names)
```
OpenAI:      #22C55E (green)
Anthropic:   #3B82F6 (blue)
Binance:     #F59E0B (amber)
GitHub:      #A1A1AA (gray)
Custom:      #8B5CF6 (purple)
```

---

## 3. TYPOGRAPHY

### 3.1 Font Families
```css
--font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
--font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', 'Consolas', monospace;
```

### 3.2 Type Scale
```
Display:   48px  weight 700  line-height 1.1   tracking -0.02em   (landing hero only)
H1:        24px  weight 700  line-height 1.2   tracking -0.02em   (page titles)
H2:        20px  weight 600  line-height 1.3   tracking -0.01em   (section headings)
H3:        16px  weight 600  line-height 1.4   tracking 0         (card titles)
H4:        14px  weight 600  line-height 1.5   tracking 0         (sub-labels)
Body:      14px  weight 400  line-height 1.6   tracking 0         (default text)
Body SM:   13px  weight 400  line-height 1.5   tracking 0         (table cells, secondary)
Caption:   12px  weight 500  line-height 1.4   tracking 0.02em    (labels, badges)
Overline:  11px  weight 600  line-height 1.3   tracking 0.06em    (uppercase section labels)
Mono:      13px  weight 400  line-height 1.5   tracking 0         (hashes, addresses, code)
```

### 3.3 When to Use Mono Font
- API endpoint paths: `/v1/chat/completions`
- Wallet/contract addresses: `0xa3f2...c891`
- Policy hashes
- Cost values in tables: `$0.03`
- CLI commands: `fishnet init`
- Timestamps in audit log
- Port numbers: `localhost:8472`

---

## 4. SPACING

4px base grid. Every spacing value is a multiple of 4.

```
4px    — Tight inline gaps (icon-to-badge)
8px    — Icon-to-text gaps, badge internal padding
12px   — Input vertical padding
16px   — Button horizontal padding, small card padding
20px   — Standard card padding
24px   — Default card padding, section gaps
32px   — Between card groups
40px   — Page section padding
48px   — Large section breaks
64px   — Page-level outer padding
```

---

## 5. BORDER RADIUS

```
6px    — Badges, tags, tiny elements
8px    — Buttons, inputs
12px   — Cards, panels
16px   — Modals, large cards
9999px — Pill badges, status dots, avatars
```

---

## 6. ELEVATION

**Dark theme**: Use BORDERS for elevation hierarchy, NOT shadows.
```
Level 0 (root):    #0A0A0B background, no border
Level 1 (surface): #111113 background, 1px solid #2A2A2E border
Level 2 (raised):  #1A1A1D background, 1px solid #2A2A2E border
Level 3 (hover):   #222225 background
```

**Light theme** (login page only): Use subtle shadows.
```
shadow-sm:  0 1px 2px rgba(0,0,0,0.05)
shadow-md:  0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -2px rgba(0,0,0,0.05)
shadow-lg:  0 10px 15px -3px rgba(0,0,0,0.08), 0 4px 6px -4px rgba(0,0,0,0.04)
```

---

## 7. TRANSITIONS

```
Fast:   100ms ease   — Tiny hover color changes
Base:   150ms ease   — Button hover, input focus, nav item hover
Slow:   250ms ease   — Sidebar collapse, page transitions
```

No animation longer than 300ms. This is a security tool.

---

## 8. RESPONSIVE BREAKPOINTS

```
Mobile:   < 768px    — Sidebar hidden (hamburger menu), 1-col grid
Tablet:   768-1024px — Sidebar collapsed (icon-only, 72px), 2-col grid
Desktop:  > 1024px   — Full sidebar (260px), 4-col metric grid
```

---

## 9. COMPONENT SPECIFICATIONS

### 9.1 Buttons

**Primary (Brand CTA)**
```
Background: #E63946
Text: #0A0A0B (dark text on red)
Height: 40px
Padding: 0 20px
Border-radius: 8px
Font: 14px, weight 600
Hover: #CC2D3B background, scale(1.01)
Active: scale(0.99)
```

**Secondary (Ghost)**
```
Background: transparent
Border: 1px solid #2A2A2E
Text: #F5F5F7
Hover: #222225 background
```

**Danger**
```
Background: #EF4444
Text: white
```

**Button sizes:**
```
SM:  height 32px, padding 0 14px, font 13px
MD:  height 40px, padding 0 20px, font 14px  (default)
LG:  height 44px, padding 0 28px, font 15px
```

### 9.2 Text Inputs

```
Background: #161618
Border: 1px solid #2A2A2E
Border-radius: 8px
Height: 40px
Padding: 0 14px
Font: 14px, color #F5F5F7
Placeholder: #71717A
Focus: border #E63946, box-shadow 0 0 0 3px rgba(230,57,70,0.15)
```

Light theme variant (login page):
```
Background: #FFFFFF
Border: 1px solid #E4E4E7
Focus: border #E63946, ring rgba(230,57,70,0.10)
```

### 9.3 Cards

```
Background: #111113
Border: 1px solid #2A2A2E
Border-radius: 12px
Padding: 24px
```

### 9.4 Status Badges (Pill)

```
Padding: 4px 10px
Border-radius: 9999px
Font: 12px, weight 500

Approved/Running:  bg rgba(34,197,94,0.12),  text #22C55E
Denied/Stopped:    bg rgba(239,68,68,0.12),  text #EF4444
Warning:           bg rgba(245,158,11,0.12), text #F59E0B
Info:              bg rgba(59,130,246,0.12),  text #3B82F6
```

### 9.5 Tables

```
Header row:    bg #111113, text #A1A1AA, font 11px weight 600 UPPERCASE tracking 0.06em
Body rows:     border-bottom 1px solid #1F1F23
Row hover:     bg #222225
Cell padding:  12px horizontal, 12px vertical
No alternating row colors.
```

### 9.6 Metric Cards

```
Layout: Grid, 4 columns desktop / 2 tablet / 1 mobile
Background: #111113
Border: 1px solid #2A2A2E
Border-radius: 12px
Padding: 20px
Top accent: 1px line at top edge in the metric's semantic color, 20% opacity

Contents:
- Top-left: 36x36px rounded icon container (semantic color at 12% opacity bg)
- Top-right: Trend arrow + percentage (green up / red down)
- Value: 28px weight 700, #F5F5F7
- Label: 12px weight 500 UPPERCASE tracking 0.04em, #71717A
- Optional: progress bar below (1.5px tall, rounded-full)
```

---

## 10. ICON SYSTEM

Use **Lucide React** (`lucide-react` on npm). Consistent stroke width of 2.

**Sizes:**
```
14px — Inline with caption text
16px — Inline with body text, inside badges
18px — Nav items, inside metric cards
20px — Nav items (alternative), button icons
24px — Feature icons, section headers
32px — Empty state illustrations
```

**Key icon mappings:**
```
Dashboard home:     LayoutDashboard
Credentials:        Key
Policies:           Sliders
Audit Log:          FileText
Analytics:          BarChart3
Onchain:            Wallet
Exchange:           Globe
Alerts:             AlertTriangle
Settings:           Settings
Approved:           CheckCircle
Denied:             XCircle or ShieldAlert
Running status:     green dot (div, not icon)
Collapse sidebar:   ChevronLeft / ChevronRight
Add:                Plus
Delete:             Trash2
Search:             Search
Export:             Download
Sign out:           LogOut
Shield/Security:    Shield, ShieldCheck
Clock/Time:         Clock
Eye toggle:         Eye / EyeOff
```

---

## 11. SIDEBAR SPECIFICATION

```
Width expanded:  260px
Width collapsed: 72px (icon-only mode)
Background:      #111113
Border-right:    1px solid #2A2A2E
Height:          100vh, fixed position
```

### 11.1 Structure (top to bottom)

```
┌─────────────────────────┐
│  LOGO AREA (h: 64px)    │  Brand icon (32x32 red square, rounded-md, white Shield icon)
│  [icon] Fishnet          │  + "Fishnet" text (15px, weight 700)
│                          │  Border-bottom: 1px solid #1F1F23
├─────────────────────────┤
│  NAV SECTION             │  Vertical list, 4px gap between items
│                          │
│  ● Dashboard             │  Each item: height 40px, padding 0 12px, radius 8px
│    Credentials           │
│    Policies              │  ACTIVE state:
│    Audit Log             │    - bg: rgba(230,57,70,0.12)
│    Analytics             │    - text: #E63946
│                          │    - left edge: 3px wide bar, rounded-r, #E63946
│  ─── divider ───         │    - icon color: #E63946
│                          │
│    Alerts [3]            │  INACTIVE state:
│    Settings              │    - text: #A1A1AA
│                          │    - hover: bg #222225, text #F5F5F7
│                          │
│                          │  Alert badge: 18px circle, bg #EF4444, white text, 10px font
├─────────────────────────┤
│  BOTTOM SECTION          │  Border-top: 1px solid #1F1F23
│                          │
│  ● Running   v0.1.0     │  Green dot (8px, with ping animation) + "Running" text
│  [◀ Collapse]            │  Collapse toggle button
│  [↪ Sign Out]            │  Sign out: text #71717A, hover text #EF4444
└─────────────────────────┘
```

### 11.2 Collapsed State (72px)
- Only show icons, centered
- Logo: only the red square icon, no text
- Nav items: only icons, centered, no labels
- Alert badge becomes a small 8px red dot at top-right of icon
- Status: only the green dot
- Collapse button: shows ChevronRight icon

---

## 12. PAGE SPECIFICATIONS

---

### ═══════════════════════════════════════
### PAGE 1: LOGIN / SIGNUP
### ═══════════════════════════════════════

**Theme**: LIGHT (this is the only light-themed page)
**Route**: `/login`
**Layout**: Split screen — 52% left panel, 48% right panel
**Mobile**: Stack vertically, form on top, brand panel hidden

#### 12.1 LEFT PANEL (Brand/Hero)

```
Background: #08080A (near black)
Full height, overflow hidden

LAYERS (back to front):
1. Base color: #08080A solid
2. Grid overlay: 48px grid lines in rgba(230,57,70,0.03)
3. Diagonal accent lines: repeating -45deg, #E63946 at 0.015 opacity, every 80px
4. Radial glow: centered, 600px circle, #E63946 at 6% center fading to transparent
5. Animated scan line: horizontal 1px line, rgba(230,57,70,0.20),
   moves from top to bottom over 8 seconds, linear, infinite loop

CONTENT (positioned with flex, justify-between, padding 48px):

TOP:
  [red square 40x40, rounded-lg, Shield icon white] + "Fishnet" text white 20px bold

CENTER:
  Headline (42px, bold, tracking -0.03em, #F5F5F7):
    "The only door
     between your agent
     and the world."        ← "and the world." in #E63946

  Subtext (15px, #71717A, max-width ~420px):
    "Local-first cryptographic security proxy. Your credentials
     never leave your machine. Every request evaluated, every action audited."

  Feature pills (flex-wrap, gap 8px):
    Each pill: border 1px solid #1F1F23, bg #111113 at 60% opacity + backdrop-blur
    Icon (14px, #E63946) + Label (12px, #A1A1AA)
    Pills: "Encrypted Vault" (Lock icon), "Policy Engine" (Shield), "Permit Signing" (Fingerprint)

BOTTOM:
  Green dot (6px, pulse animation) + "localhost:8473 · nothing leaves your machine"
  Font: 12px, mono, #52525B
```

#### 12.2 RIGHT PANEL (Form)

```
Background: #FAFAFA
Centered vertically, max-width 400px, padding 24px horizontal

MOBILE-ONLY LOGO (hidden on desktop):
  Same red square + "Fishnet" text, shown only on < 1024px

HEADER:
  Title: 26px, bold, #18181B
    Login mode:  "Welcome back"
    Signup mode: "Create your account"
  Subtitle: 14px, #71717A
    Login:  "Sign in to access your Fishnet dashboard."
    Signup: "Set up Fishnet to protect your agent's credentials."

FORM (vertical stack, 16px gap between fields):

  [Signup only] Full Name field:
    Label: "Full Name" — 13px weight 500 #18181B, margin-bottom 6px
    Input: white bg, #E4E4E7 border, 40px height, placeholder "Yash Sharma"

  Email field:
    Label: "Email Address"
    Input: placeholder "you@example.com"

  Password field:
    Label row: "Password" left, [Login only] "Forgot?" link right (#E63946, 12px)
    Input: placeholder "Enter your password"
    Eye/EyeOff toggle icon at right edge of input (#A1A1AA, hover #52525B)

  [Signup only] Confirm Password field:
    Same style as password, with its own eye toggle

  Submit button:
    Full width, height 40px, bg #E63946, text white 14px weight 600
    "Sign In" or "Create Account" + ArrowRight icon (16px)
    Hover: #CC2D3B
    Subtle shadow: 0 1px 2px rgba(0,0,0,0.05)

DIVIDER:
  Horizontal line with "or" centered, #E4E4E7 line, #A1A1AA text 12px

CLI HINT BOX:
  Rounded-lg, border #E4E4E7, bg #F5F5F5, padding 16px
  Label: "Set up via CLI instead" — 12px weight 500 #52525B
  Code block: bg white, border #E4E4E7, rounded-md, padding 8px 12px
    "$ fishnet init" — 13px mono, #18181B, $ symbol in #A1A1AA

TOGGLE LINK:
  Center aligned, 14px, #71717A
  "Don't have an account?" + "Sign up" button in #E63946
  (or reverse for signup mode)
```

#### 12.3 Login ↔ Signup Toggle Behavior
- Clicking "Sign up" / "Sign in" toggles the form mode in-place
- Signup mode ADDS: Full Name field (above email) + Confirm Password field (below password)
- Signup mode REMOVES: "Forgot?" link
- Title and subtitle text change
- Button text changes
- No page navigation — just state toggle

---

### ═══════════════════════════════════════
### PAGE 2: DASHBOARD (with sidebar)
### ═══════════════════════════════════════

**Theme**: DARK
**Route**: `/dashboard`
**Layout**: Sidebar (260px) + Main content area (flex-1)

#### 12.4 Overall Dashboard Layout

```
┌──────────┬──────────────────────────────────────────────┐
│          │  MAIN CONTENT AREA                           │
│          │  ┌──────────────────────────────────────────┐ │
│ SIDEBAR  │  │ Page content, max-width 1280px           │ │
│ (260px)  │  │ padding: 24px                            │ │
│          │  │                                          │ │
│ see      │  │ (Outlet renders child route here)        │ │
│ spec     │  │                                          │ │
│ above    │  │                                          │ │
│          │  └──────────────────────────────────────────┘ │
└──────────┴──────────────────────────────────────────────┘
```

**Mobile top bar** (shown < 768px when sidebar is hidden):
```
Height: 56px, bg #111113, border-bottom 1px solid #2A2A2E
Left: Hamburger (Menu icon) → opens sidebar as overlay
Center: Brand icon + "Fishnet" text
```

---

#### 12.5 DASHBOARD HOME PAGE (default `/dashboard` child route)

##### Header Row
```
Left:  Title "Dashboard" (22px, bold, #F5F5F7)
       Subtitle "Monitoring proxy activity on localhost:8472" (13px, mono for the port, #71717A)
Right: Live indicator pill — border #2A2A2E, bg #111113
       Green dot (8px, ping animation) + "Live" text (#22C55E, 12px weight 500)
```

##### Metric Cards (4-column grid)
```
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ ▲ +12.3%        │ │                 │ │ ▲ All healthy   │ │ ▼ +3 today      │
│                 │ │                 │ │                 │ │                 │
│ [Activity icon] │ │ [Dollar icon]   │ │ [Zap icon]      │ │ [XCircle icon]  │
│                 │ │                 │ │                 │ │                 │
│ 1,247           │ │ $18.53          │ │ 4               │ │ 23              │
│ TOTAL REQUESTS  │ │ TODAY'S SPEND   │ │ ACTIVE SERVICES │ │ DENIED REQUESTS │
│                 │ │ ████████████░░  │ │                 │ │                 │
│                 │ │ $20.00 limit    │ │                 │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘

Card 1: icon bg rgba(230,57,70,0.12), icon color #E63946, top accent #E63946
Card 2: icon bg rgba(245,158,11,0.12), icon color #F59E0B, top accent #F59E0B
         HAS progress bar (92.6% filled), bar turns red > 90%
Card 3: icon bg rgba(34,197,94,0.12), icon color #22C55E, top accent #22C55E
Card 4: icon bg rgba(239,68,68,0.12), icon color #EF4444, top accent #EF4444
```

##### Warning Banners (below metrics, only shown if warnings exist)
```
┌─ [⚠ icon, amber bg] ──────────────────────────────────── [Dismiss] ─┐
│  OpenAI daily budget at 92.6% — $18.53 of $20.00 used               │
│  Ongoing                                                              │
└──────────────────────────────────────────────────────────────────────┘

┌─ [🛡 icon, red bg] ───────────────────────────────────── [Dismiss] ─┐
│  System prompt hash changed for Anthropic service                    │
│  14 min ago                                                          │
└──────────────────────────────────────────────────────────────────────┘

Border color: warning → rgba(245,158,11,0.2), danger → rgba(230,57,70,0.2)
Icon container: 32x32, rounded-lg, semantic muted bg
```

##### Two-Column Section (below warnings)

**LEFT column (2/5 width): Spend by Service**
```
Card title: "Spend by Service" — 14px weight 600 #F5F5F7

For each service:
  Label row: service name (13px, #A1A1AA) ←→ "$12.40 / $15.00" (13px, mono, #F5F5F7 / #71717A)
  Progress bar: height 8px, rounded-full, bg #1A1A1D
    Fill color: service color (turns #F59E0B if > 80%)

Services with mock data:
  OpenAI:    $12.40 / $15.00  (green bar)
  Anthropic: $5.80  / $10.00  (blue bar)
  Binance:   $0.33  / $5.00   (amber bar)
  GitHub:    $0.00  / $2.00   (gray bar, empty)
```

**RIGHT column (3/5 width): Recent Activity**
```
Card header: "Recent Activity" left ←→ "View all" link (#E63946, 12px) right
  Border-bottom: 1px solid #1F1F23

Each row (hover bg #222225):
┌─[icon]─[●]──Service Name  /v1/chat/completions──────────────$0.03──⏰ 2m ago─┐

  Decision icon: 28x28 rounded-lg container
    Approved: bg rgba(34,197,94,0.1), CheckCircle #22C55E
    Denied:   bg rgba(239,68,68,0.1), ShieldAlert #EF4444

  Service dot: 6px circle in service color

  Service name: 13px weight 500 capitalize #F5F5F7
  Action path:  12px mono #71717A, truncate if long
  [If denied]: reason text below action, 11px #EF4444

  Cost: 13px mono #A1A1AA (or "—" if no cost)
  Time: 11px #71717A with Clock icon (12px)

Mock data rows (8 entries):
  1. openai    /v1/chat/completions       approved  $0.03   2 min ago
  2. anthropic /v1/messages               approved  $0.08   5 min ago
  3. openai    /v1/chat/completions       DENIED    —       8 min ago   "rate limit exceeded"
  4. binance   GET /api/v3/ticker/price   approved  —       12 min ago
  5. openai    /v1/chat/completions       approved  $0.02   15 min ago
  6. binance   POST /sapi/v1/capital/withdraw DENIED —      18 min ago  "endpoint blocked"
  7. anthropic /v1/messages               approved  $0.12   22 min ago
  8. github    DELETE /repos/fishnet/test  DENIED    —       30 min ago  "destructive action blocked"
```

---

#### 12.6 OTHER DASHBOARD PAGES (stub specs)

These pages should be implemented as simple placeholders with just a title, subtitle, and an empty-state card. The frontend dev should build only the Login and Dashboard Home as full pages; everything else is a routed stub.

**Credentials** `/dashboard/credentials`
```
Title: "Credentials"
Subtitle: "Manage your encrypted API keys. Values are never displayed."
Action button: "Add Key" (brand, Plus icon)
Stub content: card with Key icon (32px, #71717A), centered
  "No credentials yet"
  "Add your first API key to get started."
```

**Policies** `/dashboard/policies`
```
Title: "Policies"
Subtitle: "Configure security rules in fishnet.toml"
Stub: Sliders icon, "Policy Editor — Coming Soon"
```

**Audit Log** `/dashboard/audit`
```
Title: "Audit Log"
Subtitle: "Tamper-evident record of every proxied request"
Action: "Export CSV" (secondary button, Download icon)
Stub: FileText icon, "Audit entries will appear here"
```

**Analytics** `/dashboard/analytics`
```
Title: "Analytics"
Subtitle: "Spend trends, request volume, and usage patterns"
Stub: BarChart3 icon, "Charts will be rendered here"
```

**Alerts** `/dashboard/alerts`
```
Title: "Alerts"
Subtitle: "Warnings, anomalies, and security events"
Stub: AlertTriangle icon, "No active alerts"
```

**Settings** `/dashboard/settings`
```
Title: "Settings"
Subtitle: "Configure Fishnet proxy and security options"
Stub: Settings icon, "Settings panel — Coming Soon"
```

---

## 13. ROUTING STRUCTURE

```
/login                → LoginPage (light theme, no sidebar)
/dashboard            → DashboardLayout wrapper (dark theme, sidebar)
  /dashboard          → DashboardHome (index route)
  /dashboard/credentials → CredentialsPage
  /dashboard/policies    → PoliciesPage
  /dashboard/audit       → AuditLogPage
  /dashboard/analytics   → AnalyticsPage
  /dashboard/alerts      → AlertsPage
  /dashboard/settings    → SettingsPage
/*                    → Redirect to /login
```

The login form "Sign In" button navigates to `/dashboard`.
The sidebar "Sign Out" button navigates to `/login`.

---

## 14. REQUIRED NPM PACKAGES

```
react-router-dom     — Client-side routing
lucide-react         — Icons
tailwindcss          — Styling (v4, with @tailwindcss/vite plugin)
@tailwindcss/vite    — Vite integration for Tailwind v4
```

---

## 15. DO's AND DON'Ts

**DO:**
- Use the exact hex values from this document
- Maintain 4px grid alignment
- Use Inter for UI text, JetBrains Mono for code/hashes/addresses/ports
- Use Lucide React for all icons
- Dark theme for dashboard, light theme ONLY for login
- Border-based elevation in dark mode (no shadows)
- Truncate long hashes with monospace font + ellipsis

**DON'T:**
- Don't use colors not defined here
- Don't use font sizes outside the type scale
- Don't add gradients anywhere (exception: login left panel)
- Don't use box-shadows in dark mode
- Don't use animations longer than 300ms
- Don't round borders above 16px (except 9999px pill)
- Don't show actual API key values anywhere — only "Encrypted" badge

---

*This document is v1.0. If a design decision changes, update this file first.*
