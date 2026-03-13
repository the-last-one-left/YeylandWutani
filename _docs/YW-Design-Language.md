# Yeyland Wutani Design Language

**Yeyland Wutani LLC — "Building Better Systems"**

This document defines the standard visual design system used across all YW-branded HTML reports and tools. Follow these conventions to maintain a consistent look and feel.

---

## Brand Identity

| Property       | Value                          |
|----------------|--------------------------------|
| Company        | Yeyland Wutani LLC             |
| Tagline        | Building Better Systems        |
| Primary Color  | `#FF6600` (YW Orange)          |
| Dark Orange    | `#CC5200`                      |
| Light Orange   | `#FFF3E6` (tint, backgrounds)  |
| Grey           | `#6B7280`                      |

---

## CSS Variables

Always declare these at the root of every report stylesheet:

```css
:root {
    --yw-orange:       #FF6600;
    --yw-dark-orange:  #CC5200;
    --yw-light-orange: #FFF3E6;
    --yw-grey:         #6B7280;
}
```

---

## Color Palette

### Semantic Status Colors

| Status   | Background | Text      | Usage                      |
|----------|------------|-----------|----------------------------|
| Success  | `#d4edda`  | `#155724` | Active, enabled, started   |
| Warning  | `#fff3cd`  | `#856404` | Suspended, caution, premium|
| Danger   | `#f8d7da`  | `#721c24` | Stopped, disabled, critical|
| Neutral  | `#e2e3e5`  | `#383d41` | Unknown, default state     |
| Info     | `#FFF3E6`  | `#CC5200` | Informational notes        |

### Run History Status Colors

| Status    | Color     |
|-----------|-----------|
| Success   | `#28a745` |
| Failed    | `#dc3545` |
| Cancelled | `#f0ad4e` |
| Running   | `#4a90d9` |

---

## Layout

### Page Background
```css
body {
    background: #F5F5F5;
    color: #333;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 13px;
    line-height: 1.5;
}
```

### Container
```css
.container {
    max-width: 1800px;
    margin: 0 auto;
    padding: 24px 30px;
}
```

---

## Header

Orange gradient bar spanning the full width, with company wordmark left and report title right.

```css
.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 30px;
    background: linear-gradient(135deg, var(--yw-orange), var(--yw-dark-orange));
    color: white;
}
```

**Wordmark (text-only fallback):**
```html
<span style="font-size:26px;font-weight:900;letter-spacing:2px;color:white;">YEYLAND WUTANI</span>
<span style="color:rgba(255,255,255,0.7);font-size:12px;margin-left:6px;letter-spacing:1px;">LLC</span>
```

**Report title (right side):**
```html
<div class="report-title" style="font-size:18px;font-weight:700;color:white;">Report Name</div>
<div class="report-sub" style="font-size:11px;color:rgba(255,255,255,0.75);margin-top:3px;">Generated TIMESTAMP</div>
```

---

## Section Headers

```css
.section-title {
    color: var(--yw-dark-orange);
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 12px;
    margin-top: 24px;
    padding-bottom: 6px;
    border-bottom: 2px solid var(--yw-orange);
}
```

---

## Cards & Panels

### Summary Metric Cards

```css
.summary-card {
    background: white;
    border-radius: 8px;
    padding: 14px;
    text-align: center;
    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
    border-left: 4px solid var(--yw-orange);
}
.summary-card.warning { border-left-color: #f0ad4e; }
.summary-card.danger  { border-left-color: #dc3545; }
.summary-card .num   { font-size: 28px; font-weight: 800; color: var(--yw-orange); }
.summary-card .label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #666; margin-top: 4px; }
```

Grid layout:
```css
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 12px;
}
```

### Content Sections / Breakdown Boxes

```css
.section {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
    overflow: hidden;
    margin-bottom: 20px;
}
.section-header {
    background: var(--yw-light-orange);
    padding: 12px 16px;
    border-bottom: 2px solid var(--yw-orange);
    color: var(--yw-dark-orange);
    font-weight: 700;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
```

### Collapsible Flow/Item Cards

```css
.flow-card {
    background: white;
    border-radius: 8px;
    margin-bottom: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    border-left: 4px solid #ddd;
}
.flow-card.card-started   { border-left-color: #28a745; }
.flow-card.card-stopped   { border-left-color: #dc3545; }
.flow-card.card-suspended { border-left-color: #f0ad4e; }
.flow-header:hover { background: #FFF7F2; }
```

---

## Badges

```css
.badge          { display: inline-block; font-size: 10px; padding: 2px 8px; border-radius: 4px; font-weight: 600; white-space: nowrap; }
.badge-success  { background: #d4edda; color: #155724; }
.badge-danger   { background: #f8d7da; color: #721c24; }
.badge-warning  { background: #fff3cd; color: #856404; }
.badge-neutral  { background: #e2e3e5; color: #383d41; }
```

Usage: `<span class="badge badge-success">Active</span>`

---

## Tables

```css
th  { background: var(--yw-light-orange); color: var(--yw-dark-orange); font-weight: 600; padding: 8px 12px; border-bottom: 2px solid var(--yw-orange); text-align: left; }
td  { padding: 7px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:hover { background: #FFF7F2; }
```

---

## Informational Notes

For inline callout boxes (e.g. API limitations, fallback notices):

```css
.info-note {
    background: var(--yw-light-orange);
    border-left: 3px solid var(--yw-orange);
    padding: 10px 14px;
    font-size: 12px;
    color: var(--yw-dark-orange);
    border-radius: 0 4px 4px 0;
    margin: 4px 0;
}
```

---

## Buttons

```css
.btn           { border-radius: 4px; padding: 5px 14px; cursor: pointer; font-size: 12px; font-weight: 600; border: none; }
.btn-primary   { background: var(--yw-orange); color: white; }
.btn-secondary { background: white; color: #555; border: 1px solid #ddd; }
.btn:hover     { opacity: 0.85; }
```

---

## Footer

Always include at the bottom of every report:

```css
.footer        { text-align: center; padding: 24px; color: #888; font-size: 11px; margin-top: 20px; border-top: 1px solid #ddd; }
.footer .tagline { color: var(--yw-orange); font-weight: 600; font-size: 13px; margin-bottom: 4px; }
```

```html
<div class="footer">
    <div class="tagline">Building Better Systems</div>
    Yeyland Wutani LLC &mdash; [Report Name] &mdash; Generated [TIMESTAMP]
</div>
```

---

## Client Report Variant (Pacific Office Automation)

When producing client-facing reports (POA branding), use:

| Property      | Value                    |
|---------------|--------------------------|
| Primary Color | `#00A0D9` (POA Blue)     |
| Tagline       | "Problem Solved."        |
| Company       | Pacific Office Automation|

Swap `var(--yw-orange)` → POA blue; keep the same structural patterns.

---

## Links

```css
a { color: var(--yw-orange); text-decoration: none; }
a:hover { text-decoration: underline; }
```

---

## Print Styles

```css
@media print {
    body { background: #FFF; }
    .flow-detail { display: block !important; }
    .filter-bar  { display: none; }
}
```
