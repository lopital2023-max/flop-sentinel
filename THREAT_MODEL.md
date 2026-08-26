# FLOP Sentinel threat model

最終更新: 2026-08-27

## 守るもの

- 利用者のwallet、seed、private key、個人情報
- 管理者のTechnocore用Ed25519秘密鍵とmacOS Keychain解除値
- 公式sourceの観測履歴、snapshot、manifest、reviewed checkpointの完全性
- 公開サイトとJSON APIを閲覧する利用者のブラウザ
- GitHub repositoryとPages deploymentの完全性

FLOP Sentinelはwalletを接続せず、利用者に秘密情報を入力させません。Technocore用DID鍵は暗号資産walletとは別物です。

## 信頼境界

```text
user text / URL ── local parser only ── verdict
                         X no fetch / no shell

pinned HTTPS sources ── byte limit + host allowlist ── raw snapshot
                                                   ├── JSON/text normalization
                                                   └── SHA-256 manifest

local encrypted keystore ── macOS Keychain unlock ── Ed25519 checkpoint
                         X never available to GitHub Actions or the browser

GitHub Actions ── unsigned observations only ── GitHub Pages
```

## 想定する攻撃者

- 類似ドメイン、userinfo、Punycode、偽contractを貼る第三者
- Technocoreのworld-writable room／noteへ悪意ある文章やcommandを書く第三者
- 監視対象のHTML、JSON、repository descriptionへ命令文やscript文字列を混入できる第三者
- 依存packageやGitHub Actionを侵害するsupply-chain攻撃者
- 公開artifactを書き換えようとするhosting／repository攻撃者
- 管理者端末へ侵入し、keystoreまたはKeychainへアクセスする攻撃者

## 「外部の命令を実行しない」ための制御

1. 利用者が貼ったURLは`URL`として構文解析するだけで、DNS lookup、HTTP request、redirect追跡を行いません。
2. 監視collectorはコードと設定の両方に固定した4 URLだけをGETし、redirect先hostも固定します。
3. 取得したHTMLは正規化用の文字列として扱い、DOMへ挿入せず、shell、`eval`、module loaderへ渡しません。
4. raw snapshotはSHA-256計算対象のbytesとしてのみ読み、`.snapshot`拡張子、attachment、`nosniff`で配信します。
5. 画面への動的表示は`textContent`とAstroのescapeを利用し、`innerHTML`、`set:html`、`document.write`を使いません。
6. production codeで起動するOS programは、macOS Keychain用の固定path `/usr/bin/security`だけです。shellを介さず固定subcommandと検証済み引数を配列で渡します。
7. TechnocoreへのPOSTは明示的な`--execute-external-write`が必要で、送信originを`https://technocore.chat`へ固定します。GitHub Actionsからは実行しません。
8. 外部forkのpull requestでは提出者が変更できるcode、test、package script、workflowを自動実行しません。CIは管理者がreview済みrefに対して明示的に起動します。定期monitorだけが`contents: write`を持ち、固定pathの観測dataだけをstageします。

したがって、Technocore roomなどに「このshell commandを実行せよ」と書かれても、そのroom自体をcollectorは読みません。固定source内に同様の文字列が現れても、snapshot／文字列dataとして保存されるだけで実行経路へ入りません。

## CI/CDの制御

- GitHub Actionsは公式`actions/*`だけを使用し、release tagではなく完全なcommit SHAへ固定します。
- Node version、Astro version、依存treeは`.nvmrc`と`package-lock.json`で固定します。
- CI installは`npm ci --ignore-scripts`を使い、dependency lifecycle scriptを無効にします。
- CIは`workflow_dispatch`のみで、外部pull request eventからは起動しません。tokenは`contents: read`のみです。
- GitHub repository設定でも、すべてのexternal contributorのfork workflowに管理者承認を要求します。
- Pages jobだけが`pages: write`と`id-token: write`を持ちます。
- scheduled monitorはdefault branchだけで動き、fork／pull request eventでは起動しません。
- scheduled monitorにkeystore、Keychain解除値、wallet secret、repository secretを渡しません。
- 自動観測manifestは署名されません。reviewed checkpointは管理者端末で明示フラグを付けた場合だけ作成します。

## 証跡が保証する範囲

- SHA-256はmanifestが参照するexact bytesの変更を検出します。
- `previousManifestHash`と`previousAttestationHash`は公開履歴の途中変更を検出します。
- Ed25519 signatureは表示DIDに対応するprivate keyでpayloadが署名されたことを検証します。

証跡は、公式sourceの内容が真実・安全であること、FLOP Labsの承認、airdrop資格、on-chain状態を保証しません。repository全体を削除して別履歴へ置換できる権限者への対抗には、第三者mirrorや外部timestampが別途必要です。

## 残余リスク

| リスク | 現在の低減策 | 残る限界 |
|---|---|---|
| 公式origin自体の侵害 | hash変化を記録し、最新観測とreview済み観測を区別 | 侵害された内容の真偽は自動判定できない |
| GitHub account侵害 | Actions最小権限、署名chain、private vulnerability reporting | repository削除・Pages差替えはaccount保護に依存 |
| npm supply chain | lockfile integrity、exact version、CI lifecycle script無効 | build時にdependency codeは実行される |
| GitHub Action supply chain | official actionをcommit SHA固定 | 固定commit自体の脆弱性は残る |
| 悪意あるfork pull request | PR eventでcodeを実行せず、全external contributorのworkflow承認を必須化 | 管理者が未確認codeを手動実行する人的リスクは残る |
| 管理者端末侵害 | AES-256-GCM keystore、Keychain、秘密非表示 | 署名中の強い端末侵害、memory取得には非対応 |
| GitHub Pages header制約 | HTML meta CSPも併用、inline script/style禁止 | `frame-ancestors`等のresponse headerはPagesで強制できない |
| 同時更新 | workflow concurrency | 複数のローカルprocessによる同時index更新は非対応 |

## 脆弱性報告

秘密情報、未公開exploit、account侵害の兆候はpublic issueへ書かず、GitHub repositoryのPrivate vulnerability reportingから報告してください。一般的なsource訂正や誤検知はissue templateを使用できます。
