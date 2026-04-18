# Vendor icons

Source SVGs used to derive the `<symbol>` definitions embedded inline in
[`../hero-banner.svg`](../hero-banner.svg), the one branded visual in the repo.

## Attribution

Nine of the ten icons come from **[Simple Icons](https://simpleicons.org/)**,
a curated collection of SVG brand icons released under **CC0 1.0
Universal** (public domain). The project maintains the icons specifically
for documentation and application use, and the license is deliberately
permissive:

> The Simple Icons project and all its assets are licensed under CC0 1.0
> Universal (public domain). This means you can use them for any purpose
> without attribution (though attribution is always appreciated).

Source: https://github.com/simple-icons/simple-icons

The files in this directory are the unmodified SVGs as fetched from
`cdn.jsdelivr.net/npm/simple-icons@latest/icons/<slug>.svg`:

| File | Simple Icons slug | Use in architecture |
|---|---|---|
| `amazonwebservices.svg` | `amazonwebservices` | AWS IAM target |
| `microsoftazure.svg` | `microsoftazure` | Entra ID target (Microsoft Entra is the modern name for Azure AD) |
| `googlecloud.svg` | `googlecloud` | GCP IAM target |
| `snowflake.svg` | `snowflake` | Snowflake HR source + Snowflake target |
| `databricks.svg` | `databricks` | Databricks HR source + Databricks target |
| `clickhouse.svg` | `clickhouse` | ClickHouse HR source |
| `okta.svg` | `okta` | Okta identity source |
| `microsoftentra.svg` | `microsoft` | Microsoft Entra identity source (umbrella Microsoft mark used as a stand-in) |
| `googleworkspace.svg` | `google` | Google Workspace identity source (umbrella Google mark used as a stand-in) |

## Stand-in product marks

Simple Icons includes a direct `okta` icon, so the Okta source can use the
product mark directly.

Simple Icons does **not** currently expose a dedicated `microsoftentra` or
`googleworkspace` product icon. Until the repo adopts vendor-licensed product
artwork or another acceptable open icon source, these files intentionally use
the umbrella `microsoft` and `google` brand marks as documentation-safe
stand-ins for:

- Microsoft Entra
- Google Workspace

That keeps the visual set honest about source families without implying that
these are official product-specific marks.

## Workday — generic glyph

Workday is **not** in the Simple Icons library. Rather than reproduce
the official Workday mark (which requires adherence to their brand
guidelines), the architecture diagram uses a **generic person silhouette**
drawn as a simple inline SVG path inside the main file:

```
M12 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8zm0 10c4.42 0 8 2.69 8 6v2H4v-2c0-3.31 3.58-6 8-6z
```

This is a universal "user" icon shape (head circle + body half-arc) in
the same 24×24 viewBox as the Simple Icons files so it lines up visually.
It is not a reproduction of any brand mark.

## Trademarks

AWS, Azure, GCP, Okta, Microsoft, Google, Snowflake, Databricks, ClickHouse,
and Workday are
trademarks of their respective owners. Their use in the architecture
diagram is nominative — identifying the products as components of a
real-world IAM departures pipeline — and conforms to the usage patterns
each vendor's brand guidelines permit for technical documentation.

## Why fetch locally instead of hotlinking

The main architecture SVG embeds the icon paths inline as `<symbol>`
definitions rather than `<image href>` references. This keeps the SVG
**self-contained**: it renders identically whether it's viewed on
GitHub, in an offline clone, in a rendered PDF export, or in any tool
that doesn't allow external network fetches. The downloaded source
files in this directory are kept only for provenance and future
re-generation.

## Regenerating

```bash
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/amazonwebservices.svg" \
  -o "docs/images/vendor-icons/amazonwebservices.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/microsoftazure.svg" \
  -o "docs/images/vendor-icons/microsoftazure.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/googlecloud.svg" \
  -o "docs/images/vendor-icons/googlecloud.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/snowflake.svg" \
  -o "docs/images/vendor-icons/snowflake.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/databricks.svg" \
  -o "docs/images/vendor-icons/databricks.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/clickhouse.svg" \
  -o "docs/images/vendor-icons/clickhouse.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/okta.svg" \
  -o "docs/images/vendor-icons/okta.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/microsoft.svg" \
  -o "docs/images/vendor-icons/microsoftentra.svg"
curl -fsSL -A "Mozilla/5.0" \
  "https://cdn.jsdelivr.net/npm/simple-icons@latest/icons/google.svg" \
  -o "docs/images/vendor-icons/googleworkspace.svg"
```

Then re-run the path-extraction + inline-embed script documented in the
PR that introduced the icons.
