# Making a release

This page is for whoever makes Immune's installer package. A person who installs Immune from the package needs no developer tools and builds nothing. No release has been published yet.

## What the package holds

`./release` makes one installer package, `Immune-<version>.pkg`, with the version from `Cargo.toml`. It places two things, both owned by root:

| Path | What |
|---|---|
| `/usr/local/bin/immune` | the core, a real file, not a link |
| `/Applications/Immune.app` | the optional menu-bar app, which runs the core at `/usr/local/bin/immune` |

The package runs no script, before or after it places the files, and starts nothing. Each person who wants their account watched runs `immune install` once. Installer's last page says that Immune is installed and does not watch the Mac yet, and to run `immune install` to start it. The app does not start the core yet. A package that ends with "installed" while nothing watches would be false calm.

The package installs only on Apple Silicon with the macOS that `app/Info.plist` names in `LSMinimumSystemVersion`, today 15.0. These are requirements of its distribution file, so an Intel Mac or an older macOS is refused before anything is placed, and Installer does not offer to install Rosetta to read the package.

The app's bundle is not relocatable and is replaced as a whole (`BundleIsRelocatable` false, `BundleOverwriteAction` upgrade, in `packaging/component.plist`). A developer's own build of the app has the same bundle identifier, and a relocatable bundle would be installed over that build wherever it is, instead of in `/Applications`.

### Adopted and Immune's own

Adopted:

- A signed and notarised flat package made only with Apple's tools: `codesign`, `pkgbuild`, `productbuild`, `notarytool` and `stapler`. Santa, osquery and Tailscale ship their macOS command line tools this way ([Santa](https://northpole.security/docs/santa/deployment/install-package), [osquery](https://osquery.readthedocs.io/en/stable/installation/install-macos/), [Tailscale](https://tailscale.com/kb/1065/macos-variants)).
- A package that starts no service, as osquery's does.
- Apple's signing order and options: each piece of code signed on its own, inside out, with the hardened runtime, a secure timestamp and an explicit identifier, and no `--deep` ([Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac)). Only the outermost container, the package, is notarised, and its ticket is stapled to it ([Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow), [Packaging Mac software for distribution](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)).
- Notary credentials kept in a keychain profile made once with `notarytool store-credentials`, so the script never sees a password or a key (`man notarytool`).
- `arm64` in the distribution's architectures, without which Installer evaluates the package under Rosetta (`man productbuild`).

Immune's own:

- The core is a file in `/usr/local/bin`, not inside the app with a link to it, as Santa and osquery do. The app is optional: closing or deleting it must never stop the core. Any administrator account can change `/Applications`, and a folder the package creates in `/usr/local/bin` is root's.
- The package runs no script, and each user starts their own job with `immune install`. A root script that loads a job for the person at the console fails at the login window, under device management, with fast user switching and during setup, and `immune install` refuses root.
- The last page says that nothing watches yet.

## The owner's one-time steps

These are done once in the Apple Developer account, by its Account Holder, on the Mac that signs. They follow [Create Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates) and `man notarytool`.

1. Under Membership, read the team's name and Team ID. Everyone who installs Immune sees that name in Installer, in Gatekeeper's dialogs and in Login Items.
2. On the signing Mac, make a certificate signing request in Keychain Access, so the private key is made there and never leaves it.
3. Create a Developer ID Application certificate from that request.
4. Create a Developer ID Installer certificate the same way.
5. Download both certificates and open them, so Keychain Access pairs them with the key.
6. In App Store Connect, Users and Access, create a team API key with the Developer role and download its `.p8` file, which is offered once. An app-specific password for the Apple Account also works.
7. Store the credentials in a keychain profile once, then delete the `.p8` file:

   ```sh
   xcrun notarytool store-credentials "<profile name>" --key <path to the .p8> --key-id <key id> --issuer <issuer id>
   ```

8. Export both identities with their key to an encrypted `.p12` file and keep it offline. Each kind of Developer ID certificate can be created five times only, and revoking one stops every copy signed with it from opening.

No App ID or provisioning profile is needed while Immune claims no restricted entitlement.

## The three names

`./release` takes the identities and the profile from the environment and nowhere else. Nothing about the team is written in the repository.

| Name | Holds |
|---|---|
| `IMMUNE_SIGN_APP` | the Developer ID Application identity, as `security find-identity -v -p codesigning` prints its name: `Developer ID Application: <team name> (<team id>)` |
| `IMMUNE_SIGN_INSTALLER` | the Developer ID Installer identity: `Developer ID Installer: <team name> (<team id>)` |
| `IMMUNE_NOTARY_PROFILE` | the profile name given to `notarytool store-credentials` |

## Making the package

From a clean checkout of the commit being released, on an Apple Silicon Mac with the prerequisites of `./build` and `app/build`:

```sh
export IMMUNE_SIGN_APP="Developer ID Application: <team name> (<team id>)"
export IMMUNE_SIGN_INSTALLER="Developer ID Installer: <team name> (<team id>)"
export IMMUNE_NOTARY_PROFILE="<profile name>"
./release
```

Before it builds anything, `./release` refuses when one of the three names is not set, on an Intel Mac, and when the working tree has changes that are not committed. It then:

1. builds the core with `./build` and the app with `app/build --core-at /usr/local/bin/immune`, which records that path in the app without looking for a file there;
2. places both in a folder laid out as the Mac will be, without extended attributes;
3. signs the core with the identifier `ai.nuanu.immune.core` and the app with its bundle identifier, both with the hardened runtime and a timestamp and with no entitlements, and verifies both signatures;
4. makes the component package `ai.nuanu.immune.pkg` with root as the owner and no scripts, and the signed product package from `packaging/distribution.xml` and the pages in `packaging/resources/`;
5. reads the package back: only the core and the app in its payload, no scripts, and its signature;
6. submits it with `notarytool submit --wait`, saves Apple's log as `Immune-<version>.notary.json` beside the package and prints any issue the log names, even when Apple accepted the package;
7. staples the ticket, validates it and asks Gatekeeper (`spctl -a -t install`) about the package;
8. prints the SHA-256 of the package, to publish with it.

The package and the log are in `target/release-pkg/`. The package's path is printed on stdout and everything else on stderr. A step that fails stops the script with the step's name after the tool's own words; a notarisation Apple did not accept says where the log is. Most submissions finish within 15 minutes.

`./release --unsigned` builds the same payload into `Immune-<version>-unsigned.pkg`, signed only ad hoc as `./build` and `app/build` sign, and neither signs nor notarises the package. It needs none of the three names and also runs on a tree with uncommitted changes. It is for looking inside, with `pkgutil --expand` and `pkgutil --payload-files`, and cannot be given to anyone.

## Checking a release on a clean account

These checks are made once for the first signed release, on a user account or a virtual machine that has never had Immune, and again when the package's form changes.

1. Notarisation of the core under the hardened runtime: the log `./release` saved says `Accepted` and names no issue.
2. The installed core runs signed: after installing, `immune install`, then `immune run` and `immune status` in a new terminal. `codesign -dv --verbose=4 /usr/local/bin/immune` shows the identifier `ai.nuanu.immune.core`, the Developer ID Application authority and the `runtime` flag.
3. Login Items: System Settings, General, Login Items & Extensions shows Immune's job under the team's name; `sudo sfltool dumpbtm` lists it.
4. Gatekeeper on a download: download the package with Safari and open it, once online and once with the network off. The stapled ticket lets it open offline.
5. An update under a running job: install a package of one version, run `immune install`, install a package of the next version. `launchctl print "gui/$(id -u)/ai.nuanu.immune.watch"` should show a new pid within a minute, running the new core.
6. No relocation beside a developer's build: with a developer's build of the app present elsewhere, install the package. `pkgutil --files ai.nuanu.immune.pkg` and `/var/log/install.log` show the app placed in `/Applications`, and the developer's build is unchanged.

Also check owners: `ls -ld /Applications /Applications/Immune.app /usr/local/bin /usr/local/bin/immune` shows the app, the core and a `/usr/local/bin` the package created owned by `root`, and `/Applications` as it was before. A `/usr/local/bin` that existed before keeps its owner. If that owner is a user, as an earlier Homebrew on an Intel Mac left it, that user can replace the core.

## Updating and removing

To update, install the new package over the old one. The app is replaced as a whole and the core file is replaced. A running app keeps the old version until it is opened again.

macOS has no uninstaller. To remove what the package placed, run as each user who ran `immune install`:

```sh
immune uninstall
```

Quit the app from its panel, then, as an administrator:

```sh
sudo rm -rf /Applications/Immune.app
sudo rm -f /usr/local/bin/immune
sudo pkgutil --forget ai.nuanu.immune.pkg
```

Each user's store and the app's notification settings are kept. To remove them too, each user runs:

```sh
rm -rf "$HOME/Library/Application Support/ai.nuanu.immune"
defaults delete ai.nuanu.immune
```

The event collector is not in the package. If it was installed from a checkout, its own script removes it, as [the collector's page](event-level.md) says.
