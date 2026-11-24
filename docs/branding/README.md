# Rakshak visual identity

The original mark combines a green person/leaf and safety check within charcoal protective arcs. The user's reference supplied the care/protection theme and palette; its artwork was not copied into the app. Created24 November2026 using the built-in image-generation tool, then resized deterministically for Android. This is generated artwork, not a claim of trademark clearance.

- Master: [rakshak-logo.png](rakshak-logo.png), transparent PNG.
- App0.17.4/code47 adds the logo to the launcher and home header. Detection models, thresholds and explanations retain code46 behavior; measured model results in the report remain from their stated builds.
- Adaptive foreground occupies60% of Android's108dp icon canvas to retain padding under circular/squircle masks. Android13+ receives a monochrome themed icon. Notification status glyph remains a simple readable shield.
- To regenerate density resources: install `Pillow==13.0.0`, then run `python tools/branding/generate_android_icons.py` from the repository root.

Generation prompt:

> Use case: logo-brand. Create a single original logo mark for Rakshak, an Android personal safety app that detects network intrusions, scam SMS and phishing links. Take only conceptual inspiration from a care/protection emblem of green people above charcoal hands: design a distinctly new compact geometric emblem, not a redraw. A pair of sweeping dark charcoal protective arcs subtly form a rounded shield around one simple fresh-green human/leaf figure, with an elegant small negative-space check suggesting safety. Flat vector-like solid shapes, refined balanced curves, bold recognizable silhouette at48 pixels, green and deep charcoal palette, no gradients, no bevels, no shadows. Center the entire mark within the central60 percent of a square canvas, generous transparent padding, transparent background. Symbol only, no lettering, no text, no border, no device mockup. Make it warm, calm, trustworthy and contemporary, suitable as a finished Android app icon.
