// The scan catalogue — the one place that maps "what a person wants to assess" to the asset kind
// and engines the backend actually runs. It drives the guided New-scan flow. Nothing here is new
// capability: every kind and engine key already exists in the platform; this is the plain-language
// front door to them.

export interface ScanType {
  id: string;
  icon: string;
  label: string;
  blurb: string;              // one line: what this scans
  assetKind: string;          // the AssetKind the backend expects
  engines: string[];          // sensible default engines for this kind
  identifierLabel: string;
  identifierPlaceholder: string;
  inputHint: string;          // what to put in, in plain words
  exposure: string;           // sensible default exposure
  network: boolean;           // true = active network testing (needs authorization)
}

export const SCAN_TYPES: ScanType[] = [
  {
    id: "website", icon: "🌐", label: "Website",
    blurb: "A live web application or site.",
    assetKind: "web", engines: ["dast"],
    identifierLabel: "Website URL", identifierPlaceholder: "https://example.com",
    inputHint: "The https:// address of the site. Active testing needs an authorization on file.",
    exposure: "public", network: true,
  },
  {
    id: "api", icon: "🔌", label: "API",
    blurb: "A REST API with an OpenAPI / Swagger document.",
    assetKind: "api", engines: ["api"],
    identifierLabel: "API base URL", identifierPlaceholder: "https://api.example.com",
    inputHint: "The base URL. Add the OpenAPI/Swagger document on the asset to get the deep audit.",
    exposure: "public", network: true,
  },
  {
    id: "android", icon: "📱", label: "Mobile app — Android",
    blurb: "An Android .apk, analysed statically.",
    assetKind: "mobile_app", engines: ["mobile"],
    identifierLabel: "App name or package", identifierPlaceholder: "com.acme.app",
    inputHint: "Upload the .apk to the asset. Analysed offline — no emulator needed.",
    exposure: "isolated", network: false,
  },
  {
    id: "ios", icon: "🍎", label: "Mobile app — iOS",
    blurb: "An iOS .ipa, analysed statically.",
    assetKind: "ios_app", engines: ["ios"],
    identifierLabel: "App name or bundle id", identifierPlaceholder: "com.acme.app",
    inputHint: "Upload the .ipa to the asset. Info.plist, entitlements and the binary are read.",
    exposure: "isolated", network: false,
  },
  {
    id: "network", icon: "📡", label: "Home network / Router",
    blurb: "Your router and the devices on your LAN.",
    assetKind: "network_host", engines: ["host_posture"],
    identifierLabel: "Network name", identifierPlaceholder: "Home network",
    inputHint: "Run the local agent (docs/LOCAL_AGENT.md) and submit its posture report.",
    exposure: "internal", network: false,
  },
  {
    id: "server", icon: "🖥️", label: "Server (Linux)",
    blurb: "A Linux server's hardening posture.",
    assetKind: "server_host", engines: ["host_posture"],
    identifierLabel: "Server name or host", identifierPlaceholder: "prod-web-01",
    inputHint: "Run the local agent on the server and submit its posture report.",
    exposure: "internal", network: false,
  },
  {
    id: "cloud", icon: "☁️", label: "Cloud account",
    blurb: "AWS / Azure / GCP posture from a collector export.",
    assetKind: "cloud_account", engines: ["cspm"],
    identifierLabel: "Account name or id", identifierPlaceholder: "aws-prod-123456789012",
    inputHint: "Assessed from a read-only collector export attached to the asset.",
    exposure: "public", network: false,
  },
  {
    id: "container", icon: "🐳", label: "Container image",
    blurb: "A Docker image — CVEs, config, and an SBOM.",
    assetKind: "container_image", engines: ["container", "sca", "secrets"],
    identifierLabel: "Image reference", identifierPlaceholder: "registry/acme/app:1.4.2",
    inputHint: "Provide the image archive on the asset. Packages, Dockerfile and secrets are read.",
    exposure: "internal", network: false,
  },
  {
    id: "k8s", icon: "☸️", label: "Kubernetes",
    blurb: "Kubernetes manifests — RBAC, securityContext, exposure.",
    assetKind: "k8s_manifest", engines: ["k8s", "iac", "secrets"],
    identifierLabel: "Cluster or app name", identifierPlaceholder: "acme-prod-cluster",
    inputHint: "Provide the manifests in the asset's workspace or content.",
    exposure: "internal", network: false,
  },
  {
    id: "source", icon: "💻", label: "Source code",
    blurb: "A git repository — SAST, dependencies, secrets, SBOM.",
    assetKind: "repo", engines: ["secrets", "sast", "sca"],
    identifierLabel: "Repository URL", identifierPlaceholder: "https://github.com/acme/app.git",
    inputHint: "A git URL (or code you supply). The default engines cover code, deps and secrets.",
    exposure: "public", network: false,
  },
];
