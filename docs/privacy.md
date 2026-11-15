# What a Raye account keeps

This page is written from the code in this repository, not from an
intention, and a test keeps it that way: `server/tests/privacy.rs` reads the
migrations and the list of synced settings and fails if this page names a
table that does not exist, misses one that does, or gets the list of
settings wrong. A privacy page the code contradicts is worse than no page,
because it is believed.

Nothing here is online. There is no Raye account server running, no real
account, and the desktop side stays out of sight unless
`RAYE_ACCOUNT_PREVIEW=1` is set. What follows describes what the prototype
would keep if it were switched on.

**Raye works the same without an account.** Nothing in the system needs one,
and nothing asks twice.

## The short version

| | |
|---|---|
| Kept | your email address, your name, your picture, the settings on the list below, your app library, one row per PC, and hashes of your password and tokens |
| Not kept | your IP address, what you browse, your files, what you run, when you use your PC, or anything outside the list below |
| Who can read it | you; and whoever runs the server, except for what is hashed or sealed |
| Taking it with you | `GET /v1/me/export` gives the whole lot as one JSON file |
| Getting rid of it | `POST /v1/me/delete`, with your password again; every row goes at once |

## The eleven tables, and what each is for

Every one of them hangs off `accounts` with `ON DELETE CASCADE`: deleting
the account empties all of them in one statement.

| Table | What it holds | Why |
|---|---|---|
| `accounts` | email, whether it is confirmed, the Argon2id **hash** of the password, display name, the 256 px picture, a counter, two timestamps, and the two-step fields below | the account itself |
| `devices` | a name you can change, the model string from the firmware, the Raye version, an Ed25519 **public** key, created and last-seen times | Your devices, and binding each refresh token to its PC |
| `settings` | one row per setting on the list below: the value, a revision, when it changed and which PC changed it | the settings that follow you |
| `store_library` | app id, where it came from, when it was added | your Store library |
| `device_installs` | app id per device | so the Store can say "install on this PC" |
| `access_tokens` | SHA-256 of the token, which device, when it expires | 15-minute sessions, revocable at once |
| `refresh_tokens` | SHA-256 of the token, which device, expiry, whether it was spent | 60-day sessions that rotate, so a copied one is detected |
| `oauth_codes` | SHA-256 of the code, where it may be sent, the PKCE challenge, a 60-second expiry | one sign-in, in flight |
| `pending_signups` | SHA-256 of the link, the address, the Argon2id hash of the chosen password, the name, a 24-hour expiry | a sign-up waiting for its address to be confirmed; removed when the link is opened or once expired |
| `signin_codes` | one per account: an HMAC of the 6-digit sign-in code (under a key the running server holds in memory only), a 10-minute expiry, the number of wrong tries | the code sent by email at sign-in; removed once used, after 5 wrong tries, or replaced by a new one |
| `web_sessions` | SHA-256 of the cookie, a CSRF token, when the password or passkey was last proven, last seen, a 14-day expiry | being signed in on account.rayelinux.com; removed at sign-out, password change (other browsers) or expiry |
| `passkeys` | the credential id, the public key and counter as the passkey library stores them, the name you gave it, when it was added and last used | signing in with a passkey; nothing that could be used to sign in elsewhere |
| `webauthn_ceremonies` | the challenge of a passkey request in flight, 2 minutes, used once | adding or using a passkey |
| `email_tokens` | SHA-256 of the link, the address it proves, a 24-hour expiry, whether it was spent | confirming your address |
| `password_resets` | SHA-256 of the link, a 30-minute expiry, whether it was spent | resetting a forgotten password |
| `totp_recovery_codes` | SHA-256 of each code, whether it was spent | getting back in without your phone |

### What is never there in a readable form

- **Your password.** Only an Argon2id hash (19 MiB, two passes), with a salt.
  It cannot be turned back into your password.
- **Any token, code or recovery code.** Only a SHA-256. A copy of the
  database cannot be replayed as a session, and a lookup is a probe on the
  hash of whatever was presented - never a comparison against a stored secret.
- **Your two-step secret.** `accounts.totp_secret` is sealed with
  XChaCha20-Poly1305 under a key that lives in the server's environment
  (`RAYE_ACCOUNT_TOTP_KEY`), not in the database. A database dump alone does
  not hand over anyone's second factor. `totp_last_step` is a number: the
  last 30-second slot you used, kept so a code works once.
- **Your private device key.** The server stores the public half. The private
  half never leaves your PC's keyring.

## The 153 settings that sync

The server refuses any key that is not on this list and checks the shape of
every value, so the account cannot be used as general storage - and so this
section can be an exact description rather than a summary.

Twelve have a reader of their own, because Raye applies them through a tool
rather than a config key:

| Group | Keys |
|---|---|
| Personalization | `appearance.colorScheme`, `appearance.accentColor`, `appearance.wallpaper` |
| Taskbar | `taskbar.pins`, `taskbar.alignment`, `start.pins` |
| Language | `region.language`, `region.formats`, `input.keyboardLayouts` |
| Accessibility | `accessibility.animationSpeed`, `accessibility.cursorSize`, `accessibility.stickyKeys` |

A wallpaper is kept **by name**, and only for wallpapers that ship with Raye.
No file of yours is uploaded. A setting left at its default is absent, so a
new PC never pushes its defaults over your choices.

The other 141 are single entries of a config file in `~/.config`, copied as
they are: a yes/no, a number, or a short text of at most 200 characters with
no line break, never starting with `!` or `-` and holding no `/`, `..`, `$`
or backquote, so a value from the account can never be read as a command or
a path. They come from `common/sync-table.json`, which lists every key
Raye Settings writes (a test fails when Settings writes a new one the file
does not mention).

### Personalization (6)

| File | Group | Key | Where you change it |
|---|---|---|---|
| `kdeglobals` | `Raye` | `TransparencyEffects` | Personalization > Colors |
| `kdeglobals` | `Sounds` | `Enable` | Personalization > Sounds |
| `kdeglobals` | `Sounds` | `Theme` | Personalization > Sounds |
| `kwinrc` | `Plugins` | `blurEnabled` | Personalization > Colors |
| `kwinrc` | `Plugins` | `contrastEnabled` | Personalization > Colors |
| `rayerc` | `Windeco` | `AccentBorder` | Personalization > Colors |

### Taskbar and Start (15)

| File | Group | Key | Where you change it |
|---|---|---|---|
| `raye-taskbarrc` | `Taskbar` | `AllDisplays` | Personalization > Taskbar |
| `raye-taskbarrc` | `Taskbar` | `MultiDisplayButtons` | Personalization > Taskbar |
| `rayeshellrc` | `Start` | `Folders` | Personalization > Start > Folders |
| `rayeshellrc` | `Start` | `Layout` | Personalization > Start |
| `rayeshellrc` | `Start` | `MostUsed` | Personalization > Start |
| `rayeshellrc` | `Start` | `RecentApps` | Personalization > Start |
| `rayeshellrc` | `Start` | `Recommended` | Personalization > Start |
| `rayeshellrc` | `Taskbar` | `Alignment` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `Badges` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `Combine` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `Flashing` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `MultiDisplayApps` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `Search` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `ShowDesktopCorner` | Personalization > Taskbar |
| `rayeshellrc` | `Taskbar` | `TaskView` | Personalization > Taskbar |

### Language and region (13)

| File | Group | Key | Where you change it |
|---|---|---|---|
| `kcminputrc` | `Keyboard` | `RepeatDelay` | Time & language > Typing |
| `kcminputrc` | `Keyboard` | `RepeatRate` | Time & language > Typing |
| `plasma-localerc` | `Formats` | `LC_ADDRESS` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_MEASUREMENT` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_MONETARY` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_NAME` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_NUMERIC` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_PAPER` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_TELEPHONE` | Time & language > Language & region |
| `plasma-localerc` | `Formats` | `LC_TIME` | Time & language > Language & region |
| `rayeshellrc` | `Clock` | `ShowDate` | Time & language > Date & time |
| `rayeshellrc` | `Clock` | `ShowSeconds` | Time & language > Date & time |
| `rayeshellrc` | `Clock` | `Use24h` | Time & language > Date & time |

### Accessibility (31)

| File | Group | Key | Where you change it |
|---|---|---|---|
| `kaccessrc` | `Bell` | `VisibleBell` | Accessibility > Audio |
| `kaccessrc` | `Keyboard` | `BounceKeys` | Accessibility > Keyboard |
| `kaccessrc` | `Keyboard` | `Gestures` | Accessibility > Keyboard |
| `kaccessrc` | `Keyboard` | `SlowKeys` | Accessibility > Keyboard |
| `kaccessrc` | `Keyboard` | `StickyKeysAutoOff` | Accessibility > Keyboard |
| `kaccessrc` | `Keyboard` | `StickyKeysBeep` | Accessibility > Keyboard |
| `kaccessrc` | `Keyboard` | `StickyKeysLatch` | Accessibility > Keyboard |
| `kaccessrc` | `Keyboard` | `ToggleKeysBeep` | Accessibility > Keyboard |
| `kaccessrc` | `Mouse` | `MKMaxSpeed` | Accessibility > Mouse keys |
| `kaccessrc` | `Mouse` | `MKTimeToMax` | Accessibility > Mouse keys |
| `kaccessrc` | `Mouse` | `MouseKeys` | Accessibility > Mouse keys |
| `kaccessrc` | `ScreenReader` | `Enabled` | Accessibility > Screen reader |
| `kcminputrc` | `Mouse` | `cursorTheme` | Accessibility > Mouse pointer and touch |
| `kdeglobals` | `General` | `fixed` | Accessibility > Text size |
| `kdeglobals` | `General` | `font` | Accessibility > Text size |
| `kdeglobals` | `General` | `menuFont` | Accessibility > Text size |
| `kdeglobals` | `General` | `smallestReadableFont` | Accessibility > Text size |
| `kdeglobals` | `General` | `toolBarFont` | Accessibility > Text size |
| `kdeglobals` | `Raye` | `TextSize` | Accessibility > Text size |
| `kdeglobals` | `WM` | `activeFont` | Accessibility > Text size |
| `kwinrc` | `Effect-colorblindnesscorrection` | `Intensity` | Accessibility > Color filters |
| `kwinrc` | `Effect-colorblindnesscorrection` | `Mode` | Accessibility > Color filters |
| `kwinrc` | `Effect-zoom` | `EnableFocusTracking` | Accessibility > Magnifier |
| `kwinrc` | `Effect-zoom` | `EnableTextCaretTracking` | Accessibility > Magnifier |
| `kwinrc` | `Effect-zoom` | `MouseTracking` | Accessibility > Magnifier |
| `kwinrc` | `Effect-zoom` | `ZoomFactor` | Accessibility > Magnifier |
| `kwinrc` | `Plugins` | `colorblindnesscorrectionEnabled` | Accessibility > Color filters |
| `kwinrc` | `Plugins` | `magnifierEnabled` | Accessibility > Magnifier |
| `kwinrc` | `Plugins` | `shakecursorEnabled` | Accessibility > Mouse pointer and touch |
| `kwinrc` | `Plugins` | `zoomEnabled` | Accessibility > Magnifier |
| `rayeshellrc` | `Notifications` | `ToastSeconds` | Accessibility > Visual effects |

### Everything else (76)

| File | Group | Key | Where you change it |
|---|---|---|---|
| `baloofilerc` | `Basic Settings` | `Indexing-Enabled` | Privacy & security > Searching (FileSearchPage) |
| `dolphinrc` | `Raye` | `PreviewPane` | File Explorer > View |
| `dolphinrc` | `Raye` | `ShowExtensions` | System > Advanced |
| `dolphinrc` | `Raye` | `ShowHidden` | System > Advanced |
| `dolphinrc` | `Raye` | `ShowNavigationPane` | File Explorer > View |
| `kactivitymanagerd-pluginsrc` | `Plugin-org.kde.ActivityManager.Resources.Scoring` | `what-to-remember` | Privacy & security > Activity history |
| `kdeglobals` | `RecentDocuments` | `UseRecent` | Privacy & security > Activity history |
| `klipperrc` | `General` | `KeepClipboardContents` | System > Clipboard |
| `klipperrc` | `General` | `MaxClipItems` | System > Clipboard |
| `knighttimerc` | `General` | `Source` | System > Display > Night light |
| `kwinrc` | `NightColor` | `Active` | System > Display > Night light |
| `kwinrc` | `NightColor` | `Mode` | System > Display > Night light |
| `kwinrc` | `NightColor` | `NightTemperature` | System > Display > Night light |
| `kwinrc` | `Script-org.raye.snap` | `SnapAssist` | System > Multitasking |
| `kwinrc` | `Script-org.raye.snap` | `SnapBar` | System > Multitasking |
| `kwinrc` | `Script-org.raye.snap` | `SnapLayoutsOnHover` | System > Multitasking |
| `kwinrc` | `TabBox` | `DesktopMode` | System > Multitasking |
| `kwinrc` | `TabBox` | `ShowDesktopMode` | System > Multitasking |
| `kwinrc` | `Windows` | `ElectricBorderMaximize` | System > Multitasking |
| `kwinrc` | `Windows` | `ElectricBorderTiling` | System > Multitasking |
| `plasmanotifyrc` | `DoNotDisturb` | `NotificationSoundsMuted` | System > Notifications |
| `plasmanotifyrc` | `DoNotDisturb` | `WhenFullscreen` | System > Notifications |
| `plasmanotifyrc` | `DoNotDisturb` | `WhenScreenSharing` | System > Notifications |
| `plasmanotifyrc` | `DoNotDisturb` | `WhenScreensMirrored` | System > Notifications |
| `powerdevilrc` | `AC/Display` | `DimDisplayIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `AC/Display` | `LockBeforeTurnOffDisplay` | Accounts > Sign-in options |
| `powerdevilrc` | `AC/Display` | `TurnOffDisplayIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `AC/Display` | `TurnOffDisplayWhenIdle` | System > Power & battery |
| `powerdevilrc` | `AC/SuspendAndShutdown` | `AutoSuspendAction` | System > Power & battery |
| `powerdevilrc` | `AC/SuspendAndShutdown` | `AutoSuspendIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `AC/SuspendAndShutdown` | `LidAction` | System > Power & battery |
| `powerdevilrc` | `AC/SuspendAndShutdown` | `PowerButtonAction` | System > Power & battery |
| `powerdevilrc` | `Battery/Display` | `DimDisplayIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `Battery/Display` | `LockBeforeTurnOffDisplay` | Accounts > Sign-in options |
| `powerdevilrc` | `Battery/Display` | `TurnOffDisplayIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `Battery/Display` | `TurnOffDisplayWhenIdle` | System > Power & battery |
| `powerdevilrc` | `Battery/SuspendAndShutdown` | `AutoSuspendAction` | System > Power & battery |
| `powerdevilrc` | `Battery/SuspendAndShutdown` | `AutoSuspendIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `Battery/SuspendAndShutdown` | `LidAction` | System > Power & battery |
| `powerdevilrc` | `Battery/SuspendAndShutdown` | `PowerButtonAction` | System > Power & battery |
| `powerdevilrc` | `LowBattery/Display` | `DimDisplayIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `LowBattery/Display` | `LockBeforeTurnOffDisplay` | Accounts > Sign-in options |
| `powerdevilrc` | `LowBattery/Display` | `TurnOffDisplayIdleTimeoutSec` | System > Power & battery |
| `powerdevilrc` | `LowBattery/Display` | `TurnOffDisplayWhenIdle` | System > Power & battery |
| `powerdevilrc` | `LowBattery/SuspendAndShutdown` | `LidAction` | System > Power & battery |
| `powerdevilrc` | `LowBattery/SuspendAndShutdown` | `PowerButtonAction` | System > Power & battery |
| `raye-settingsrc` | `EnergySaver` | `LowerBrightness` | System > Power & battery |
| `raye-settingsrc` | `EnergySaver` | `TurnOnAt` | System > Power & battery |
| `raye-settingsrc` | `Focus` | `DoNotDisturb` | System > Focus |
| `raye-settingsrc` | `Focus` | `Minutes` | System > Focus |
| `raye-settingsrc` | `Home` | `Hidden` | Home (For you cards) |
| `raye-settingsrc` | `Network` | `RandomAddresses` | Network & internet > Wi-Fi |
| `raye-settingsrc` | `Network` | `VpnOverMetered` | Network & internet > VPN |
| `raye-settingsrc` | `Privacy` | `BackgroundAccess` | Privacy & security > App permissions > background |
| `raye-settingsrc` | `Privacy` | `BackgroundRestore` | Privacy & security > App permissions > background |
| `raye-settingsrc` | `Privacy` | `CameraAccess` | Privacy & security > App permissions > camera |
| `raye-settingsrc` | `Privacy` | `CameraRestore` | Privacy & security > App permissions > camera |
| `raye-settingsrc` | `Privacy` | `FilesAccess` | Privacy & security > App permissions > files |
| `raye-settingsrc` | `Privacy` | `FilesRestore` | Privacy & security > App permissions > files |
| `raye-settingsrc` | `Privacy` | `LocationAccess` | Privacy & security > App permissions > location |
| `raye-settingsrc` | `Privacy` | `LocationRestore` | Privacy & security > App permissions > location |
| `raye-settingsrc` | `Privacy` | `MicrophoneAccess` | Privacy & security > App permissions > microphone |
| `raye-settingsrc` | `Privacy` | `MicrophoneRestore` | Privacy & security > App permissions > microphone |
| `raye-settingsrc` | `Privacy` | `ScreenshotAccess` | Privacy & security > App permissions > screenshot |
| `raye-settingsrc` | `Privacy` | `ScreenshotRestore` | Privacy & security > App permissions > screenshot |
| `raye-settingsrc` | `StorageSense` | `Thumbnails` | System > Storage (Storage Sense) |
| `raye-settingsrc` | `StorageSense` | `TrashDays` | System > Storage (Storage Sense) |
| `raye-storerc` | `Search` | `ShowSystemPackages` | Store > Settings |
| `raye-storerc` | `Updates` | `Automatic` | Store > Settings |
| `rayeshellrc` | `AutoPlay` | `Enabled` | Bluetooth & devices > AutoPlay |
| `rayeshellrc` | `AutoPlay` | `MemoryCard` | Bluetooth & devices > AutoPlay |
| `rayeshellrc` | `AutoPlay` | `RemovableDrive` | Bluetooth & devices > AutoPlay |
| `rayeshellrc` | `Notifications` | `LockBadges` | System > Notifications |
| `rayeshellrc` | `Sound` | `VolumeChime` | System > Sound |
| `rayeshellrc` | `Taskbar` | `AllDesktops` | System > Multitasking |
| `rayeshellrc` | `Taskbar` | `EndTask` | System > Advanced |

Each switch in Settings › Raye backup turns off a whole group, and turning
one off stops both halves: nothing is sent and nothing is applied. The last
group, *Everything else*, is the switch called **Other settings**.

### What stays on this PC

Settings also writes these, and they are never sent: they describe this PC,
its hardware or its network, a moment rather than a choice, or something a
stranger could use to open the PC.

| File | Group | Key | Why it stays |
|---|---|---|---|
| `PlasmaUserFeedback` | `Global` | `FeedbackLevel` | how much this PC reports back is chosen on each PC, never raised from another one |
| `baloofilerc` | `General` | `exclude folders` | folders by path, many of them only exist on this PC |
| `kaccessrc` | `Keyboard` | `StickyKeys` | synced by its own adapter, as accessibility.stickyKeys |
| `kcminputrc` | `Mouse` | `cursorSize` | synced by its own adapter, as accessibility.cursorSize |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `disableEventsOnExternalMouse` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `disableWhileTyping` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `enabled` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `leftHanded` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `lmrTapButtonMap` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `naturalScroll` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `pointerAcceleration` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `pointerAccelerationProfileAdaptive` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `pointerAccelerationProfileFlat` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `scrollEdge` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `scrollFactor` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `scrollTwoFinger` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `tapAndDrag` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kcminputrc (written by KWin)` | `Libinput/<vendorId>/<productId>/<deviceName>` | `tapToClick` | set per mouse or touchpad: KWin keeps it under the hardware id of that device |
| `kdeglobals` | `General` | `AccentColor` | synced by its own adapter, as appearance.accentColor |
| `kdeglobals` | `General` | `BrowserApplication` | run as a command line by KDE (a value starting with ! is a shell command); never taken from the account |
| `kdeglobals` | `General` | `TerminalApplication` | run as a command line; never taken from the account |
| `kdeglobals` | `General` | `TerminalService` | names the terminal that is started; kept with TerminalApplication on this PC |
| `kdeglobals` | `General` | `accentColorFromWallpaper` | synced by its own adapter, as appearance.accentColor |
| `kdeglobals` | `KDE` | `AnimationDurationFactor` | synced by its own adapter, as accessibility.animationSpeed |
| `knighttimerc` | `General` | `SunriseStart` | sunrise and sunset worked out on this PC for where it is |
| `knighttimerc` | `General` | `SunsetStart` | sunrise and sunset worked out on this PC for where it is |
| `krdpserverrc` | `General` | `Autostart` | remote desktop on or off is a decision for each PC, not for an account |
| `kscreenlockerrc` | `Greeter/Wallpaper/org.kde.image/General` | `Image` | the lock screen picture is a file on this PC |
| `kwinrc` | `Wayland` | `InputMethod` | the on-screen keyboard is a program installed on this PC |
| `mimeapps.list` | `Added Associations` | `<mime type>` | one key per file type, and the apps it names must be installed on the other PC; not synced yet |
| `mimeapps.list` | `Default Applications` | `<mime type>` | one key per file type, and the apps it names must be installed on the other PC; not synced yet |
| `plasma-localerc` | `Formats` | `LANG` | synced by its own adapter, as region.formats |
| `plasma-localerc` | `Translations` | `LANGUAGE` | synced by its own adapter, as region.language |
| `plasma-nm` | `General` | `AirplaneModeEnabled` | airplane mode is the radio state of this PC right now |
| `plasmanotifyrc` | `Applications/<appId>` | `ShowBadges` | kept per app, one group for each app id, so it cannot be in the fixed list the server checks |
| `plasmanotifyrc` | `Applications/<appId>` | `ShowInHistory` | kept per app, one group for each app id, so it cannot be in the fixed list the server checks |
| `plasmanotifyrc` | `Applications/<appId>` | `ShowPopups` | kept per app, one group for each app id, so it cannot be in the fixed list the server checks |
| `plasmanotifyrc` | `Applications/<appId>` | `ShowPopupsInDndMode` | kept per app, one group for each app id, so it cannot be in the fixed list the server checks |
| `plasmanotifyrc` | `DoNotDisturb` | `Until` | the end of a pause (Focus, do not disturb) is a moment, not a preference |
| `raye-developerrc` | `General` | `DeveloperMode` | Developer Mode opens this PC to the network; it is never switched on from another PC |
| `raye-developerrc` | `General` | `SshPasswords` | SSH settings open this PC to the network; never set from another PC |
| `raye-settingsrc` | `Background` | `Recent` | pictures recently picked on this PC, by file path |
| `raye-settingsrc` | `EnergySaver` | `PreviousProfile` | what Energy saver goes back to, kept by this PC while it is on |
| `raye-settingsrc` | `LockScreen` | `Recent` | pictures recently picked on this PC, by file path |
| `raye-settingsrc` | `Network` | `BluetoothBeforeAirplane` | radio state this PC saves while airplane mode is on |
| `raye-settingsrc` | `Network` | `WifiBeforeAirplane` | radio state this PC saves while airplane mode is on |
| `rayeshellrc` | `Focus` | `Until` | the end of a pause (Focus, do not disturb) is a moment, not a preference |
| `spectaclerc` | `ImageSave` | `imageSaveLocation` | a folder path that may not exist on another PC |
| `spectaclerc` | `VideoSave` | `videoSaveLocation` | a folder path that may not exist on another PC |
| `~/.config/autostart/<name>.desktop` | `Desktop Entry` | `Hidden` | which apps start at sign-in follows the apps installed on this PC |
| `~/.config/kioslaverc` | `Proxy Settings` | `NoProxyFor` | proxy settings belong to the network this PC sits on |
| `~/.config/kioslaverc` | `Proxy Settings` | `Proxy Config Script` | proxy settings belong to the network this PC sits on |
| `~/.config/kioslaverc` | `Proxy Settings` | `ProxyType` | proxy settings belong to the network this PC sits on |
| `~/.config/kioslaverc` | `Proxy Settings` | `ReversedException` | proxy settings belong to the network this PC sits on |
| `~/.config/kioslaverc` | `Proxy Settings` | `ftpProxy` | proxy settings belong to the network this PC sits on |
| `~/.config/kioslaverc` | `Proxy Settings` | `httpProxy` | proxy settings belong to the network this PC sits on |
| `~/.config/kioslaverc` | `Proxy Settings` | `httpsProxy` | proxy settings belong to the network this PC sits on |
| `~/.local/share/applications/<appId>.desktop` | `Desktop Entry` | `PrefersNonDefaultGPU` | which graphics chip an app uses depends on the graphics hardware of this PC |
| `~/.local/share/applications/<appId>.desktop` | `Desktop Entry` | `X-Raye-GpuChoice` | which graphics chip an app uses depends on the graphics hardware of this PC |

Changed through a tool or D-Bus rather than a config key, and not synced:

- **power profile (power-profiles-daemon)**: the profiles a PC offers depend on its hardware.
- **time zone and automatic time (timedated)**: set for the whole PC, and follows where it is.
- **displays, brightness, night light schedule location**: per monitor and per PC.
- **Wi-Fi, VPN, Bluetooth pairings, hotspot**: networks, devices and their secrets stay on the PC.
- **sound devices and volumes**: the devices differ from PC to PC.
- **look and feel (plasma-apply-lookandfeel)**: it rewrites the panel layout; theme, colors, accent and wallpaper sync on their own.
- **per-app notification rules, startup apps, GPU per app**: keyed by app or hardware, see excluded.
- **game mode**: Settings only shows it; Raye Gaming switches it on per game.

## Your picture

Whatever you upload is **decoded once on the server and written again** as a
fresh 256 px PNG, cropped to the centre square. PNG, JPEG and WebP only, at
most 2 MiB and 4096 px a side. Re-encoding is what drops EXIF - including
the GPS location a phone writes into a photo - along with comments and
anything else aimed at a decoder. What comes back out is only pixels.

## Your IP address

Not stored. It is used, in memory only, as the key of a rate-limit counter,
so that guessing passwords and asking for reset links can be slowed down.
Those counters are pruned and die with the process; nothing writes them to
disk and no table has a column for an address.

There is **no access log**: the server installs no request-logging layer, so
no per-request record of an address, a path or a time is produced.

## What does reach the server's log

Only these, and they are worth knowing about exactly because the list is short:

- account and device **identifiers** (UUIDs) when a password is reset, when
  two-step verification is turned on or off, when a recovery code is used,
  and when a refresh token is presented twice;
- that a confirmation or reset link was presented after being spent - the
  *kind* of link, never the address it was sent to;
- the server's listening address at startup;
- **database error text** when a request fails. This one is not curated: if
  PostgreSQL names a value in a constraint message, that value is in the log.
  The log is server-side only; the client is told nothing but "something went
  wrong".

Nothing logs an email address, a password, a token, or an IP address.

## Mail

Five letters, all from `bonjour@rayelinux.com`: your sign-in code, finish creating your account,
"you already have an account" (sent instead when the address is taken),
confirm your address, and reset your password. They are handed to a local submission binary; this
server speaks no SMTP itself and holds no mail password. No letter
contains anything about your account beyond the link.

The website (account.rayelinux.com) sets one cookie for the session
(HttpOnly, Secure, SameSite=Lax) and, if you pick a language with the switch
in the top bar, one cookie that remembers it. No other cookie, no outside
script, font or image, no analytics.

A sign-up is answered with the same page whether or not the address already
has an account; no account exists until its link is opened.

A reset request is answered with the same page whether or not the address has
an account, and whether or not that account ever confirmed it. The answer is
not a way to find out who has a Raye account.

## On your PC

| What | Where | Rights |
|---|---|---|
| tokens and the device's private key | the desktop keyring, through the Secret Service API (KWallet on Raye) | the keyring's |
| name, address, switches, revisions, hashes | `~/.local/state/raye-account/state.json` | `0600` |
| the name and picture your PC had before | `~/.local/state/raye-account/picture-before-raye-account` | so signing out can put them back |
| your account picture | `~/.cache/raye-account/picture-<etag>.png` | a cache; deleting it costs a download |

`state.json` holds nothing that could act as the account - that is a test
(`the_state_file_holds_nothing_that_could_act_as_the_account`), not a claim.

Any other program running as you can ask `org.raye.Account1` on the session
bus for the device list, or sign the PC out. That is the same trust level as
your keyring, and no stronger boundary is claimed.

## Still to come, and deliberately not yet

Passwords and Wi-Fi networks are **not** synced, and will not be until they
can be end-to-end encrypted: a per-account key made on your first PC,
wrapped for each device and for a recovery passphrase, so the server only
ever holds ciphertext it cannot read. Until that exists, putting them in the
account would mean trusting whoever runs the server with them.

## Getting it all, or getting rid of it

    GET  /v1/me/export      everything, one JSON file, picture as base64
    POST /v1/me/delete      with your password again; every row cascades away

Deleting asks for the password a second time on purpose: a token taken from
one of your PCs must not be enough to wipe the account from all of them.
Database backups age out on their own schedule after a delete.
