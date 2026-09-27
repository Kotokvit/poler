# POLER Custom Source-Available & Modification Disclosure License

**Version 1.0 — effective 2026-08-30**

> Правовая основа — английский текст ниже. Перевод на русский язык (TERMS.md,
> раздел «Сводка») приводится исключительно в справочных целях; в случае
> расхождений преимущественную силу имеет английский текст.

Copyright (c) 2025–2026 POLER Engineering Core. All rights reserved.

## 1. Definitions

- **"Licensor"** means POLER Engineering Core, the author and rights holder of
  the POLER Archiver & POLER BOX software.
- **"Engine"** means the POLER Archiver and POLER BOX software, including
  source code, object code, binary distributions, documentation, build
  scripts, the format specification, and all updates and versions thereof
  distributed under this License. (Amendment v1.1, 2026-09-27: the WebLens
  browser extension is NOT part of this product family — it is a standalone
  tool of the Licensor distributed separately under its own terms.)
- **"Source Code"** means the human-readable source form of the Engine as made
  available in the Licensor's official repository.
- **"Modifications"** means any addition to, deletion from, or alteration of
  the Source Code or binary form of the Engine, including forks, patches,
  vendored copies, partial extractions of engine modules, and derivative works
  of the Engine, in source or object form.
- **"Product"** means any software application, service, platform, appliance,
  or SaaS offering that incorporates, embeds, links to, or is built upon the
  Engine or a Modification thereof, excluding the Engine itself.
- **"You" / "Your"** means the individual or entity exercising rights under
  this License.
- **"Distribute"** means to provide, sell, sublicense, host, deploy, or
  otherwise make available a Product or the Engine (or a Modification) to any
  third party, excluding Your employees and contractors under confidentiality
  obligations.
- **"Notification Email"** means `dev@poler-engine.org`, or such contact as
  published by the Licensor in the official repository.

## 2. Grant of Rights (Source-Available)

Subject to the terms of this License, the Licensor grants You a worldwide,
non-exclusive, non-transferable (except as expressly permitted by the
Licensor), revocable license to:

1. **Inspect** the Source Code for any purpose, including security review,
   evaluation, education, and interoperability research;
2. **Build** the Engine from Source Code, for Your own use on machines You
   control or control is lawfully granted to You;
3. **Use** the Engine and built binaries in accordance with the capability
   tier unlocked by Your license key (`PO1.…`, Ed25519-signed), subject to the
   quotas and feature gates enforced by the License Gate;
4. **Modify** the Engine and create Modifications for Your own internal use,
   including integration into Products, subject to Sections 3–5.

This License does not grant You any ownership in the Engine. The Engine is
licensed, not sold.

## 3. Restrictions

You shall NOT:

1. **Redistribute the Engine or its Source Code** publicly or to any third
   party outside Your organization, in source, object, or binary form,
   including publishing forks, mirrors, archives, or package registry
   uploads of the Engine. (Distributing a Product is governed by Sections
   4–5; distributing the Engine itself is prohibited.)
2. **Circumvent, disable, remove, or alter the License Gate**, including but
   limited to: patching the Ed25519 public key, hooking or spoofing the
   license status functions, forging license keys, or stripping tier/quota
   enforcement from binaries You distribute or host.
3. **Remove or obscure** copyright notices, license headers, or the
   attribution banner of the Engine.
4. **Use the Engine or Modifications** to build capabilities whose primary
   purpose is attacking third-party systems without authorization.
5. **Sublicense** the Engine or Modifications under different terms without
   written consent of the Licensor.

## 4. Mandatory Modification Notification (Notification Clause)

**This is a material condition of this License.**

1. You MUST notify the Licensor via the Notification Email, or via a GitHub
   issue in the official repository, within **fourteen (14) days** of the
   earlier of:
   a. first Distribution of any Product incorporating Modifications, or
   b. first production deployment of Modifications in any environment
      accessible to third parties, or
   c. first commercial offering of services built on Modifications.
2. The notification MUST identify: Your legal entity or name, contact
   details, the repository or product name, a summary of the nature of
   Modifications (functional description; source diff is welcome but not
   required), and the date of first Distribution/deployment.
3. Notification does NOT require disclosure of Your Product's proprietary
   code, business logic, or data — only the fact and general nature of the
   Engine Modifications.
4. Silent forking — maintaining or exploiting Modifications of the Engine in
   closed products without notification — is a material breach of this
   License and terminates Your license to the Engine with immediate effect
   (Section 9).

## 5. Commercial Use, Royalties and Tiers

1. **Community (free) tier.** Personal evaluation, research, and use within
   the daily operation quotas enforced by the License Gate is free of charge.
2. **Pro / Enterprise tiers.** Commercial Products, team use, and
   quota-free operation require an active Pro or Enterprise license key or a
   signed Enterprise Agreement with the Licensor.
3. **Royalty.** If in a given calendar quarter the aggregate gross revenue
   attributable to a Product incorporating the Engine or a Modification
   exceeds **USD 25,000**, You owe the Licensor a royalty of **5%** of such
   excess gross revenue for that quarter, payable within 45 days of quarter
   end, unless an Enterprise Agreement specifies otherwise. Gross revenue
   from a Product that merely outputs data processed by the unmodified
   Engine (e.g., reports, search results consumed by humans) is included
   only when the Engine or a Modification is embedded in, or an integral
   part of, the distributed or hosted Product.
4. **Audit right.** Upon the Licensor's written request no more than once
   per calendar year, You shall provide a good-faith statement of revenue
   attribution for Products subject to the royalty.
5. **Reporting threshold safe harbor.** Revenue below USD 10,000 per quarter
   is deemed below the reporting threshold; no statement is due for such
   quarters.

## 6. Notices and Attribution

You shall preserve and reproduce, in all copies and builds of the Engine and
Modifications: (a) this License text or an unambiguous reference to it plus
a link to the official repository, (b) all existing copyright and license
notices, (c) the License Gate binary notice. Products distributing the
Engine's runtime shall include this License text in their documentation or
license page.

## 7. Patents

The Licensor grants You a license to its necessarily infringed patent claims
by the unmodified Engine, solely for the uses permitted herein. This patent
license does not extend to Modifications that add functionality outside the
Engine's intended purpose, and terminates upon Your breach of Sections 3–5.

## 8. Support and Updates

The Licensor may, at its sole discretion, provide updates, security patches,
and support channels. Nothing in this License obligates the Licensor to
provide support, maintenance, or future versions to You.

## 9. Termination

This License terminates automatically and immediately if You breach Sections
3, 4, or 6. Upon termination You must cease all use and Distribution of the
Engine and Modifications, and delete or destroy all copies, subject to
statutory retention rights. Sections 5 (accrued royalties), 10, and 11
survive termination.

## 10. Disclaimer of Warranties

THE ENGINE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. THE ENTIRE RISK AS TO
THE QUALITY AND PERFORMANCE OF THE ENGINE IS WITH YOU.

## 11. Limitation of Liability

IN NO EVENT SHALL THE LICENSOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING BUT NOT
LIMITED TO LOSS OF DATA, LOSS OF PROFITS, OR BUSINESS INTERRUPTION) ARISING
OUT OF OR IN CONNECTION WITH THIS LICENSE OR THE USE OF THE ENGINE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. THE LICENSOR'S TOTAL AGGREGATE
LIABILITY SHALL NOT EXCEED THE AMOUNT ACTUALLY PAID BY YOU FOR THE ENGINE
LICENSE IN THE TWELVE MONTHS PRECEDING THE CLAIM.

## 12. Miscellaneous

This License is the entire agreement between You and the Licensor regarding
the Engine and supersedes any prior terms. If any provision is held
unenforceable, the remainder continues in effect. Failure to enforce any
provision is not a waiver. You may not assign this License without the
Licensor's prior written consent. The governing law is the law of the
jurisdiction of the Licensor's principal place of business, unless an
Enterprise Agreement specifies otherwise.

**Contact / Notification Email:** dev@poler-engine.org
**Official repository:** https://github.com/poler-engine-org/poler-engine
