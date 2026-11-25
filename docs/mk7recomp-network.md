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

### One-archive NAND import

The desktop build has an **Import NAND…** action. Choose one \`NAND.zip\` containing exactly one recognized NAND image (\`NAND.bin\`, \`SysNAND.bin\`, \`EmuNAND.bin\`, or \`NANDmin.bin\`) and the matching \`nand.fat16.xorpad\`. The GodMode9 \`essential.exefs\` may be embedded in the NAND image or included as a separate ZIP entry.

The XORpad is a console-specific decryption stream and is not part of an ordinary raw NAND dump. Decrypt9WIP documents **CTRNAND Padgen** as the on-console operation for generating it from the same 3DS whose NAND was dumped. The importer supports the fixed-offset pad sizes and the legacy unfixed pad sizes. It deliberately does not manufacture a replacement pad or accept a pad from a different console.

The importer now performs these local steps:

- Validates the NAND NCSD header, partition table, declared image size, presence of FIRM, embedded essential backup layout, and its SHA-256 digests.
- Extracts \`LocalFriendCodeSeed_B\`, \`SecureInfo_A\`, \`movable.sed\`, NAND CID, and OTP into the private application data folder.
- Applies the supplied CTRNAND XORpad to produce a temporary FAT16 image, discovers \`/data/<ID0>/sysdata/00010032/00000000\`, and extracts the Friends system-save DISA archive.
- Validates the DISA partition table, DPFS/IVFC hash hierarchy, SAVE filesystem, and the \`FPAC\` account / \`FPMD\` mydata records before installing them into the same local paths read by FRD.
- Creates \`nasc.json\` and a persistent per-install virtual network-adapter address. Retrying an import with the missing XORpad can add Friends records without overwriting a different console's existing signed identity or rotating the generated adapter address.

The selected archive is read in place. The multi-gigabyte NAND is not copied to application storage or uploaded. The extracted XORpad and decrypted FAT16 image are held in owner-private temporary files and removed after the import attempt. A raw NAND image or ZIP without the matching XORpad can still import the embedded device identity, but it cannot complete Friends account extraction; the UI reports that as a partial import.

**Local NAND extraction is implemented, but this is not a claim that online races now work.** The importer checks structure and SHA-256 integrity, but does not independently validate Nintendo's RSA signature on \`LocalFriendCodeSeed_B\`; Pretendo performs its signed-certificate checks during NASC login. A virtual MAC accepted by the protocol, imported account credentials, and a valid \`UID-HMAC\` still need to pass the real server's checks. Cartridge images may also require their exact 17-byte ROM ID for NASC.

The remaining end-to-end online work is after the local import:

1. Confirm the NASC request and response handling against Pretendo with an imported real console record.
2. Complete FRD login and NEX authentication, including the title's actual \`SVCLOC\` service discovery behavior.
3. Complete secure-server connection, PRUDP sessions, matchmaking, VS/battle room creation and joining, peer connectivity/NAT traversal, and real gameplay packet flow.
4. Verify two independent clients can enter the same race, finish it, and leave cleanly. A successful HTTP probe or authenticated account alone is not a race test.

The importer must never upload the raw NAND or system saves to a server. Extraction stays local. Only the protocol fields needed for a connection are sent to Pretendo over HTTPS, as the original service protocol requires.

References for the NAND preparation flow:
- [GodMode9 NAND handling and embedded essential backups](https://github.com/d0k3/GodMode9)
- [Decrypt9WIP CTRNAND Padgen](https://github.com/d0k3/Decrypt9WIP)
- [3DSFAT16tool NAND/XORpad format and offsets](https://github.com/d0k3/3DSFAT16tool)
- [3DS DISA/DIFF and save filesystem format](https://github.com/wwylele/3ds-save-tool)
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
