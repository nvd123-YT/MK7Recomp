# MK7Recomp Network: account-only online design

Status: architecture and local identity groundwork only. There is no MK7Recomp-hosted NEX service yet, and this document does not claim that online races are currently available through an account-only flow.

## Product requirement

A player who has supplied a legitimate Mario Kart 7 game dump should be able to:

1. Turn on **MK7Recomp Network** in RecompLauncher.
2. Join immediately using an automatically created anonymous installation identity.
3. Optionally link an account for recovery, cross-device use, friends, and moderation appeals.
4. Launch the game and use its normal online menus.

The player must not need to import a NAND, Friends system-save folder, LocalFriendCodeSeed, Nintendo device certificate, serial number, MAC address, BSSID, or other console-specific files.

An account is optional for first play. An identity is not optional: the service needs a stable, independent identity for matchmaking, rate limits, moderation, and save/account recovery. It is generated locally once and is not rotated as a way to get around sanctions.

## Two separate network ecosystems

### Pretendo

Pretendo remains a distinct provider. Its published policy says that emulator users still need the relevant data from a real 3DS. Pretendo's developers have explained that they previously experimented with allowing emulator users without real console data, but withdrew it after abuse. The current NASC implementation validates the device's signed LocalFriendCodeSeed and related device fields.

MK7Recomp must not fabricate a Nintendo-signed LocalFriendCodeSeed, impersonate a physical console, or send its own installation identity to Pretendo as though it were a Nintendo identity. The legacy Pretendo routing path can remain available for people who independently meet Pretendo's requirements, but it is not the intended account-only recomp experience.

References:
- https://pretendo.network/ (FAQ: emulator and real-console requirements)
- https://github.com/PretendoNetwork/website/issues/317 (Pretendo developer explanation)
- https://github.com/PretendoNetwork/account/blob/main/src/middleware/nasc.ts (NASC validation)
- https://github.com/PretendoNetwork/mario-kart-7 (public MK7 authentication and secure server)

### MK7Recomp Network

This is a separate, explicitly branded service with its own account, identity, and game-server backend. It must use its own hostnames and must never present its credentials as Pretendo or Nintendo credentials.

The client-side identity groundwork is in `crates/zakuro-core/src/network_identity.rs`:

- A random 128-bit installation ID and 256-bit installation secret are created on first use.
- The identity persists under `network/mk7recomp/identity.json` inside the application's data directory.
- On Unix, the identity directory is owner-only (0700) and the identity file is owner-read/write (0600).
- Existing malformed identity files fail closed and are not silently replaced.
- Debug output redacts the secret.
- These values are only for an MK7Recomp-owned service. They are not console credentials and are never valid for Pretendo NASC.

## Proposed online bootstrap contract

This contract is a design proposal, not an existing public API. Do not hard-code an endpoint until the service is deployed and its API is implemented.

1. The client establishes authenticated TLS with the configured MK7Recomp Network service.
2. It proves possession of its installation secret using a challenge-response exchange. The secret itself must not be sent as a bearer token in a URL or logged.
3. The service returns a stable MK7Recomp player principal and a short-lived session token.
4. The service provisions a game-specific NEX account for that principal and returns only the game credentials required by the MK7Recomp NEX client.
5. The game-facing FRD layer consumes this service-issued identity locally; it does not make an ordinary Pretendo NASC login with fabricated console information.
6. Optional account linking is handled by the MK7Recomp account service. It is used for recovery and cross-device continuity, not as a prerequisite to play.

The service must not derive identity from public hardware attributes such as a MAC address or serial number. It should store a separate stable record for each installation. If the player links multiple installations to one account, the service can associate them without making them share a device identity.

## Server architecture

A complete race requires more than an account endpoint. The planned service components are:

- **Identity and account API:** challenge-response authentication, anonymous account creation, optional account linking, session issuance, and per-installation principals.
- **NEX 2 / PRUDP v0-v1 services:** authentication and secure endpoints compatible with Mario Kart 7's actual protocol and service methods.
- **Mario Kart 7 game services:** matchmaking, VS rooms, battle rooms, friend joins, communities/rankings where supported, and ghost data as implementation permits.
- **Connectivity:** NAT discovery, peer traversal, and a relay fallback for restrictive networks. A player must not be told a race is joinable until a real session can be established.
- **Operations and moderation:** per-account and per-installation rate limits, abuse reports, ban appeals, service health, and privacy-conscious logs.

Pretendo's public Mario Kart 7 server is a useful protocol reference and is AGPL-3.0. Any code reuse or modification must preserve the applicable license and notices. Its server expects its account service's NEX data and is not, by itself, a turnkey account-only service for this recomp. Review upstream code and configuration before integrating it.

## Identity, privacy, and enforcement

- An installation identity is generated automatically and persists across normal application updates.
- A reinstall or moving data to another computer may create a new installation unless the user uses the optional account recovery flow.
- Do not include the secret in logs, crash reports, screenshots, diagnostics, or analytics.
- Do not transmit the identity to Pretendo, Nintendo, or unrelated services.
- Do not create rotating identities, auto-reset identities after bans, or market the identity system as a ban bypass. Enforcement belongs to the independent service and must be scoped to the responsible account/installation with an appeal path.
- The server must have abuse controls from its first public test; account-only onboarding must not mean anonymous, unmoderated access.

## Delivery milestones

- [x] Add secure, persistent per-install identity storage in the runtime.
- [x] Cover stable reload, independent installs, corrupt-file handling, redacted diagnostics, and Unix file permissions with unit tests.
- [ ] Add an opt-in MK7Recomp Network provider and launcher setup flow.
- [ ] Implement the identity challenge/response and account bootstrap service.
- [ ] Implement or integrate an independently hosted MK7 NEX authentication and secure server.
- [ ] Connect the game's FRD/NEX login path to the new provider without requiring a Friends-save import.
- [ ] Complete race-path diagnostics for authentication, room creation, matchmaking, NAT, and peer connectivity.
- [ ] Run two independent recomp clients through a complete VS race, then test battle rooms, disconnect/reconnect, and persistence.
- [ ] Deploy and operate a stable public service, with monitoring, moderation, and a published privacy policy.

Until the final two-client race test passes, the service must be labelled **experimental / not yet playable online**. A successful TCP connection or NEX login alone is not proof that race matchmaking works.
