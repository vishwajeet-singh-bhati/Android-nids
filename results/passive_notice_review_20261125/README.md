# Passive warnings and historical notification refresh —25 November2026

Current app: **0.18.0-passive-notices / code53**. No detector weights, thresholds
or feature definitions changed. This review does not claim to repair normal-use
model false positives or improve class recall.

## Finding

The latest matching incoming-reset network row predated the user's report:
15:19:06 IST, an unverified LAN peer to phone port7680, two packets, zero
application payload, TCP reset. The binary score was0.8913205; diagnostic type
was Unclassified. The record does not establish malicious intent, app ownership
or a successful connection. Earlier matching records were14:25,14:45 and14:59.

Opening the app refreshed **all** qualifying active historical rows through the
notification publisher, including rows no longer visibly posted. This could
make old observations appear newly detected. There were no newer network model
flags in the saved log at review. Other detector rows are not network evidence.

No traffic-blocking response path was found. The privileged command surface is
packet capture and read-only socket/interface snapshots. The app has no VPN
service or Wi-Fi/mobile-data control permission. Llama's process cleanup kills
only its own worker; stopping capture closes Rakshak's own tcpdump process.
These are not termination of other apps' TCP connections.

The previous monitor session ended cleanly with enabled=false and no runtime
error. Code51 did not log the stop-request source, so the initiating actor cannot
be established retrospectively. It must not be blamed on the detector without
evidence.

## Changes

- Refresh wording only for notifications already visible; opening the app does
  not resurrect historical alerts. Activity history and raw decisions remain.
- Title: **Incoming connection did not open**. The note explicitly says Rakshak
  observed the reset and did not block the connection. Old cached wording for
  this evidence is invalidated; unchanged non-reset v3 guidance remains usable.
- Both network-pause controls require confirmation. Cancelling should retain
  monitoring. Manual pause affects only local monitoring, not Internet access.
- New stop/lifecycle audit events record source and confirmation status.
- Add source regression tripwires against network-control permissions, VPN
  services and growth of the privileged command surface. These are review guards,
  not a formal sandbox for every possible rooted-device execution.

No blanket app/port whitelist, new benign label, silent gate veto, historical
deletion, automatic Expected feedback or network enforcement was introduced.
Two earlier code51 campaign cases remain separate; this is not a new completed
13-profile campaign or fresh accuracy evaluation.

## Validation

- App and instrumentation build passed.
- Installed Pixel hybrid contract passed, including a regression proving an
  unposted historical ID remains absent from active notifications.
- Old v3 rejected-handshake display regression passed: current wording states
  the observer did not block the connection.
- Native alignment/policy/clock checks and21 self-check rows passed;0 decision
  flips. All38 bundled assets match code51 byte for byte.
- Installation preserved saved history/preferences. Code53 final APK SHA256:
  b6f79260b9add42f56db77ed21bdebc84f90e9f5da8da78f857c001f123415e2.
- Wi-Fi and mobile-data settings matched before/after snapshots. IPv4 firewall
  policies/ordered rules matched after excluding generated timestamps and
  packet/byte counters. Snapshot equality supports this observation; it does not
  prove every future runtime behavior.
- Foreground capture and ADB connectivity verified after deployment.
- Automated own-app pause/cancel UI checks were **not completed**: the hierarchy
  was the lock screen, so no tap was injected. Confirmation UI is built/deployed,
  but its two manual paths still need an unlocked-phone check.

Private evidence is retained locally, not published as raw captures/history or
firewall contents. Rollback APKs remain local. The app warns and explains; it
does not establish compromise or block attacks automatically.
