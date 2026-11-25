# MK7Recomp Network: account-only online design

Status: architecture and local identity groundwork only. There is no MK7Recomp-hosted NEX service yet, and this document does not claim that online races are currently available through an account-only flow.

## Product requirement

A player who has supplied a legitimate Mario Kart 7 game dump should be able to:

1. Optionally import **one NAND backup** from their own 3DS in the RecompLauncher setup flow.
2. Have MK7Recomp automatically extract the signed device seed, serial/model data, and Friends system-save records it needs. No separate file selection or hand-written JSON.
3. Optionally link a Pretendo Network ID where a game feature actually needs one. Most 3DS game servers do not require a PNID.
4. Launch the game and use its normal online menus.

The approved user-facing requirement is one NAND backup, not an entire manually reconstructed 3DS installation. The application must not ask the player to separately locate LocalFriendCodeSeed_B, SecureInfo_A, Friends account/mydata files, serial number, MAC address, BSSID, AP slot, or nasc.json.

The NAND import is optional for offline play and only used when the player enables legacy Pretendo connectivity. The device identity must be the user's own signed seed and matching serial from the same backup. A per-install virtual network-adapter address may be generated and persisted where needed; it must never replace or modify the signed seed or serial. It must not be rotated to evade a ban.

A PNID is not a prerequisite for most 3DS game servers; the game-facing NEX account is separate. The importer should preserve an existing Friends/NEX account from the NAND. Where the Friends system has no NEX account yet, account creation should be handled by the supported NASC initial-registration flow rather than asking the player to create or edit account files by hand.

## Two separate network ecosystems

### Pretendo

Pretendo remains a distinct provider. Its published policy says that emulator users still need relevant data from their own real 3DS. The current NASC implementation validates the signed LocalFriendCodeSeed and checks the supplied serial and MAC format/OUI. Pretendo binds the device record to the seed hash and serial; a PNID is not required for most 3DS game servers.

MK7Recomp must extract the real signed seed and matching serial from the player's one NAND backup. It must not fabricate or rewrite the Nintendo-signed seed or substitute a random serial. The Wi-Fi MAC is a separate hardware value read from the 3DS Wi-Fi card's EEPROM rather than an ordinary CTRNAND file; the importer must provide a stable, per-install virtual adapter address only if Pretendo's protocol validation accepts that approach. The user must not be asked to type it manually.

References:
- https://pretendo.network/ (FAQ: emulator and real-console requirements)
- https://github.com/PretendoNetwork/website/issues/317 (Pretendo developer explanation)
- https://github.com/PretendoNetwork/account/blob/main/src/middleware/nasc.ts (NASC validation)
- https://github.com/PretendoNetwork/mario-kart-7 (public MK7 authentication and secure server)

### Single-file NAND import

The desktop build now has an **Import NAND…** action. It accepts either a raw NAND image or a ZIP containing exactly one recognized image named NAND.bin, SysNAND.bin, EmuNAND.bin, or NANDmin.bin. The first-stage importer:

- Validates the NCSD header, partition table, declared image size, and presence of FIRM.
- Requires the GodMode9 embedded essential.exefs block at sector 1 and validates the expected record layout and SHA-256 digests.
- Extracts LocalFriendCodeSeed_B, SecureInfo, movable.sed, and OTP into the application's private sysdata directory.
- Generates and persists a virtual Nintendo-OUI network-adapter MAC for this installation and creates nasc.json automatically.
- Reads only the first 0x2400 bytes needed to inspect the image and essential backup; it does not copy or upload the multi-gigabyte NAND.

**Not finished yet:** this first stage does not decrypt the CTRNAND FAT partition, extract the Friends system-save DISA archive, or parse its account and mydata records. As a result, this is not yet a complete Pretendo login setup and a successful import does not mean the game can join a race. The UI reports this limitation instead of claiming online readiness.

The NAND importer currently performs structural and SHA-256 integrity checks on the embedded backup. It does not independently verify Nintendo's RSA signature on LocalFriendCodeSeed_B; Pretendo still performs that server-side validation during NASC login.

The full one-file target remains:

1. Validate and identify the NAND image.
2. Decrypt/mount CTRNAND using the console-specific material in the essential backup and the required common crypto material supported by the runtime.
3. Parse the FAT filesystem and locate the Friends system-save archive at the correct ID0/system-save path.
4. Parse the DISA/DIFF structures and extract the FPAC account and FPMD mydata records locally.
5. Configure the remaining network fields automatically, preserving the imported signed seed and matching serial.
6. Complete FRD NASC login, NEX authentication, SVCLOC, and the game's real matchmaking/session path.

The importer must never upload the raw NAND or system saves to a server. Extraction stays local. Only the NASC/NEX fields required for a connection are sent to Pretendo over HTTPS, exactly as the original service protocol requires.

## MK7Recomp Network

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
- [x] Add a one-file raw/ZIP NAND import flow, validate the NCSD and GodMode9 essential.exefs structure and hashes, extract the signed-seed record, SecureInfo, movable.sed and OTP, and generate a persistent virtual adapter address plus nasc.json.
- [ ] Independently verify the LocalFriendCodeSeed_B signature against the Nintendo public key before presenting the extracted identity as valid.
- [ ] Implement the NAND/CTRNAND decryption and FAT mount pipeline.
- [ ] Parse the Friends system-save DISA/DIFF archive and extract FPAC account and FPMD mydata automatically.
- [ ] Preserve or initialize local Friends/NEX account state so users do not need to import the Friends system save separately.
- [ ] Add an opt-in MK7Recomp Network provider and launcher setup flow.
- [ ] Implement the identity challenge/response and account bootstrap service.
- [ ] Implement or integrate an independently hosted MK7 NEX authentication and secure server.
- [ ] Connect the game's FRD/NEX login path to the new provider without manual Friends-save import.
- [ ] Complete race-path diagnostics for authentication, room creation, matchmaking, NAT, and peer connectivity.
- [ ] Run two independent recomp clients through a complete VS race, then test battle rooms, disconnect/reconnect, and persistence.
- [ ] Deploy and operate a stable public service, with monitoring, moderation, and a published privacy policy.

Until the final two-client race test passes, the service must be labelled **experimental / not yet playable online**. A successful TCP connection or NEX login alone is not proof that race matchmaking works.
