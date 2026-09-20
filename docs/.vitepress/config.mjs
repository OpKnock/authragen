import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'AuthraGen',
  description: 'Vendor-neutral Agent Passport trust layer — exact-authority identity for agents',
  lang: 'en-US',
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#0ea5e9' }],
  ],
  themeConfig: {
    logo: '/logo.svg',
    nav: [
      { text: 'Guide', link: '/guide/introduction', activeMatch: '/guide/' },
      { text: 'API Reference', link: '/api/overview', activeMatch: '/api/' },
      { text: 'SDKs', link: '/sdk/javascript', activeMatch: '/sdk/' },
      { text: 'Adapters', link: '/adapters/overview', activeMatch: '/adapters/' },
      { text: 'Deployment', link: '/deployment/docker', activeMatch: '/deployment/' },
      { text: 'Security', link: '/security/model', activeMatch: '/security/' },
      {
        text: 'v2.1.0',
        items: [
          { text: 'Changelog', link: '/changelog' },
          { text: 'Protocol Spec', link: '/protocol' },
          { text: 'Comparison', link: '/comparison' },
        ]
      }
    ],
    sidebar: {
      '/guide/': [
        { text: 'Introduction', link: '/guide/introduction' },
        { text: 'Quickstart', link: '/guide/quickstart' },
        { text: 'Core Concepts', link: '/guide/concepts' },
        { text: 'Architecture', link: '/guide/architecture' },
        { text: 'Identity & Passports', link: '/guide/identity' },
        { text: 'Authorization Flow', link: '/guide/authorization' },
        { text: 'Delegation', link: '/guide/delegation' },
        { text: 'Policy Engine', link: '/guide/policy' },
        { text: 'Approvals & Quorum', link: '/guide/approvals' },
        { text: 'Revocation', link: '/guide/revocation' },
        { text: 'Audit & Accountability', link: '/guide/audit' },
      ],
      '/api/': [
        { text: 'Overview', link: '/api/overview' },
        { text: 'Authentication', link: '/api/authentication' },
        { text: 'Organizations', link: '/api/organizations' },
        { text: 'Blueprints', link: '/api/blueprints' },
        { text: 'Passports', link: '/api/passports' },
        { text: 'Delegations', link: '/api/delegations' },
        { text: 'Policies', link: '/api/policies' },
        { text: 'Authorize & Execute', link: '/api/authorize-execute' },
        { text: 'Approvals', link: '/api/approvals' },
        { text: 'Revocation', link: '/api/revocation' },
        { text: 'Verification', link: '/api/verification' },
        { text: 'Audit', link: '/api/audit' },
        { text: 'Errors', link: '/api/errors' },
      ],
      '/sdk/': [
        { text: 'JavaScript SDK', link: '/sdk/javascript' },
        { text: 'Python SDK', link: '/sdk/python' },
        { text: 'Offline Verification', link: '/sdk/offline-verification' },
      ],
      '/adapters/': [
        { text: 'Overview', link: '/adapters/overview' },
        { text: 'OpenAI', link: '/adapters/openai' },
        { text: 'Anthropic', link: '/adapters/anthropic' },
        { text: 'Gemini', link: '/adapters/gemini' },
        { text: 'MCP', link: '/adapters/mcp' },
        { text: 'A2A', link: '/adapters/a2a' },
        { text: 'n8n', link: '/adapters/n8n' },
      ],
      '/deployment/': [
        { text: 'Docker', link: '/deployment/docker' },
        { text: 'Kubernetes', link: '/deployment/kubernetes' },
        { text: 'Production Checklist', link: '/deployment/production' },
        { text: 'Configuration', link: '/deployment/configuration' },
      ],
      '/security/': [
        { text: 'Security Model', link: '/security/model' },
        { text: 'Threat Model', link: '/security/threat-model' },
        { text: 'Cryptography', link: '/security/cryptography' },
        { text: 'Production Hardening', link: '/security/hardening' },
        { text: 'Known Limitations', link: '/security/limitations' },
      ],
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/OpKnock/authragen' },
      { icon: 'npm', link: 'https://www.npmjs.com/package/authragen' },
    ],
    footer: {
      message: 'Released under the Apache-2.0 License.',
      copyright: 'Copyright © 2024-present AuthraGen Contributors',
    },
    search: {
      provider: 'local',
    },
    editLink: {
      pattern: 'https://github.com/OpKnock/authragen/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
  },
  markdown: {
    theme: 'github-dark',
    lineNumbers: true,
  },
})