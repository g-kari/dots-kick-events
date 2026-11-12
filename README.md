# dots-kick-events — dots を MCP Events で起こす発火側サーバー

dots（ChatGPT／一姫）を、OpenAI 公式ガイド「MCP Events」の仕組みで直接起こすための、イベント発火側 MCP サーバー。Cloudflare Worker として実装・デプロイ済み。

- 公式ガイド: https://developers.openai.com/plugins/build/mcp-events
- 本番 MCP エンドポイント: `https://dots-events.0g0.xyz/mcp`
- workers.dev: `https://dots-kick-events.0g0.workers.dev/mcp`（サブドメイン有効。ただしこの VM からは workers.dev への POST がタイムアウトする環境要因があるため、検証はカスタムドメインで実施）
- 実装: [worker.js](sandbox://workspace/dots-kick-events/worker.js)（単一ファイル、ランタイム依存なし。自動テストのみ `test/` 配下で Miniflare を devDependency として使用）

## 構成

- Cloudflare Worker `dots-kick-events`（アカウント 0g0）
- 永続化は **Durable Object（SQLite、クラス `Store`、単一インスタンス）に集約**。当初計画の KV は、現在の Cloudflare 接続（OAuth）の権限に KV／D1 が含まれず作成・読み取りとも 403 になったため、Workers プラットフォーム内蔵の DO に切り替えた。購読・依頼はすべて DO 内に保存され、再デプロイでも消えない。
- デプロイは Cloudflare コネクタの `execute`（API 直叩き）で行った。`wrangler.toml` はデプロイ済み構成の写し（参照用）。

## 実装したプロトコル（ガイド準拠）

MCP エンドポイント `POST /mcp`（JSON-RPC 2.0）:

| メソッド | 内容 |
|---|---|
| `initialize` | `capabilities` に `tools` と `events` を広告（Streamable HTTP） |
| `server/discover` | MCP 2.0（`2026-07-28`）向けに `resultType:"complete"`、`supportedVersions:["2026-07-28"]`、`events` 能力を返却 |
| `events/list` | イベント定義を返却（下記 `kick` 1種） |
| `events/subscribe` | 購読の作成／更新。署名付きチャレンジでコールバックを検証してから保存 |
| `events/unsubscribe` | 名前・引数・コールバックURLが一致する購読を停止（冪等、空の結果を返却） |
| `tools/list` / `tools/call` | 照合用ツール2種（下記） |

### イベント `kick`

- `delivery: ["webhook"]` のみ（ガイド通り、polling／streaming と `gap`・`terminated` 制御通知は ChatGPT 統合が非サポートのため実装しない）
- 購読引数（フィルタ）: `topic`（任意の文字列。一致する topic の依頼だけ配送）
- ペイロード `data`: `request_id`、`text`、`topic`（任意）、`created_at`

### 購読（events/subscribe）の処理

1. イベント名・引数を定義と照合。未知のフィルタ引数は `-32602`。
2. `delivery.secret` が `whsec_` 形式で Base64 デコード後 24–64 バイトであることを検証。
3. コールバックURLは HTTPS 必須。localhost／プライベートIPリテラル等を拒否（拒否時は `-32015`）。IPv6 リテラルは WHATWG URL が付ける角括弧を除去してからグループ単位で分類し、loopback（`::1`）・ULA（`fc00::/7`）・link-local（`fe80::/10`）・IPv4-mapped（埋め込み IPv4 を IPv4 ルールで判定）を拒否する。
4. 購読IDは principal（認証トークンの主体。下記「認証（OAuth 2.1）」参照）＋コールバックURL＋イベント名＋引数の canonical JSON から決定的に導出。同一IDなら更新（冪等）。購読レコードにも principal を保存し、他人の購読は参照・解除できない。
5. 保存前に、署名付きの検証リクエスト `{"type":"verification","challenge":...}` をコールバックへ送り、2xx かつチャレンジの一致を確認。失敗時は JSON-RPC エラー `-32015`（`data.reason`: `challenge_failed` / `timeout` など）。検証成功は principal＋URL 単位で24時間キャッシュし、再購読時の再チャレンジを省略。
6. 有効期限: `ttlMs` 省略時は7日、`ttlMs` 指定時は最小1時間・最大30日にクランプ、`ttlMs: null`（無期限要求）でも有限の期限を返す。結果に `refreshBefore` を含める（`cursor: null`、`truncated: false`）。
7. 秘密鍵ローテーション時（再購読で新しい secret が来た場合）は旧鍵を10分間保持し、その間は新旧両方の署名をスペース区切りで付ける（Standard Webhooks の作法）。

### 配送（Webhook）

- 依頼1件につき購読ごとに1リクエスト。ボディは `{eventId, name:"kick", timestamp, data, cursor:null}`、256 KiB 以下。
- ヘッダ: `webhook-id`（= `eventId`）、`webhook-timestamp`（Unix秒）、`webhook-signature`（Standard Webhooks の HMAC-SHA256、`v1,...`）、`X-MCP-Subscription-Id`。
- `eventId` は依頼ID＋購読IDから決定的に生成され、リトライでも不変（dots 側の重複排除に使える）。
- 一時失敗は最大3回まで指数バックオフで再試行（410／413 は再試行しない）。リダイレクトは追従しない（Workers の fetch は `redirect:"error"` 非対応のため `"manual"` にし、2xx 以外を失敗として扱うことで等価にしている）。

### 照合用ツール

| ツール | 内容 |
|---|---|
| `list_pending_requests` | 未完了（completed 以外）の依頼を新しい順に返す。引数 `limit`（任意、既定20） |
| `update_request_status` | 依頼を `acknowledged`（受領）または `completed`（完了）に更新。冪等。引数 `request_id`、`status`、`note`（任意） |

### 依頼の状態

`pending`（保存済み・未配送または配送失敗）→ `delivered`（Webhook が 2xx で受領）→ `acknowledged`（dots が受領を申告）→ `completed`（dots が完了を申告）。配送結果（購読ごと・試行回数・HTTP状態）は依頼レコードに残るので、未完了分は `list_pending_requests` で後から照合できる。

## 認証（OAuth 2.1）— 0g0-id を認可サーバーにする構成

`/mcp` は保護リソースとして認証必須。**認可サーバーは所有者自身の IdP「0g0-id」（https://id.0g0.xyz）に分離し、本 Worker はトークンを発行しないリソースサーバー専用**にした。

### 方式の経緯

- 初版の PR では「同一 Worker 内に最小構成の認可サーバーを内蔵」する方式だったが、所有者の判断で 0g0-id 方式に作り替えた。既存の信頼できる IdP があるのに自作の認証基盤（パスワードログイン・セッション・トークン保管）を増やすべきではない、というのが理由。
- 0g0-id 側に不足していた2点は 0g0-id の PR で追加した: **RFC 7591 動的クライアント登録（DCR）** と **RFC 8707 リソースインジケーターによる audience 束縛**（従来の 0g0-id はアクセストークンの `aud` が常に `client_id` で、リソースサーバーに束縛できなかった）。→ https://github.com/g-kari/0g0-id/pull/336

### 前提・依存関係（これが揃うまで本方式では動かない）

1. 0g0-id 側 PR のマージとデプロイ、本番 D1 へのマイグレーション適用。
2. 0g0-id のリソースサーバーレジストリへの本サーバーの登録: URI `https://dots-events.0g0.xyz/mcp`、許可スコープ `events:read events:subscribe requests:read requests:update`（管理 API `POST /api/resources`）。
3. 本 PR のデプロイ。

audience 検証はこの登録 URI との完全一致で行うため、登録が無い／URI がずれていれば、正規のトークンでも全て 401 になる（安全側）。

### トークン検証（リクエストごと）

| 項目 | 内容 |
|---|---|
| 形式 | 0g0-id が発行する **ES256 JWT のみ**。不透明（opaque）トークンは受理しない |
| 鍵の取得 | JWKS `https://id.0g0.xyz/.well-known/jwks.json` から `kid` で選択。10分キャッシュし、未知の `kid` では再取得して鍵ローテーションに追従（再取得は1秒に1回まで） |
| 検証内容 | 署名（ES256）、`iss` = `https://id.0g0.xyz`、`aud` = 本サーバーの resource URI、`exp` / `nbf`、`sub` の存在、スコープ（`scope` 文字列／`scp` 配列） |
| principal | トークンの `sub`。購読の所有者はこれに結び付く |

| 要素 | 内容 |
|---|---|
| 保護リソースメタデータ (RFC 9728) | `GET /.well-known/oauth-protected-resource`（`/mcp` サフィックス付きでも可）。`resource` は MCP エンドポイント URL、`authorization_servers` は `["https://id.0g0.xyz"]` |
| 認可サーバーメタデータ | 本 Worker では提供しない（404）。0g0-id の `https://id.0g0.xyz/.well-known/oauth-authorization-server` を参照 |

### スコープと認可

| スコープ | 許可される操作 |
|---|---|
| `events:read` | `events/list` |
| `events:subscribe` | `events/subscribe`、`events/unsubscribe` |
| `requests:read` | `list_pending_requests` |
| `requests:update` | `update_request_status` |
| `claude:kick` | `kick_claude`（逆方向。Muse への依頼登録） |

- トークンがない・不正・期限切れの `/mcp` 呼び出しは **401** と `WWW-Authenticate: Bearer resource_metadata="…"、scope="…"` を返す。スコープ不足は **403**（単一リクエスト時）と step-up 用の `WWW-Authenticate` を返す（バッチ内では該当メッセージだけ JSON-RPC エラー `-32003`）。
- 購読はトークンの `sub` に結び付く。別 principal が同じ（URL・名前・引数）で解除しようとしても、購読ID自体が異なるため所有者の購読には届かない（レコード側でも principal 一致を確認する二重防御）。配送対象は認証済み principal の購読のみで、認証導入前の `anonymous` 購読（自己検証用データ）には配送しない。

### 所有者制限（OWNER_SUB）

本サーバーは個人用のため、**「有効なトークンを持っている」だけでは依頼データに触れない**。スコープに加えて、データを扱うメソッド（`events/subscribe`、`events/unsubscribe`、ツール2種）はトークンの `sub` が平文変数 `OWNER_SUB`（所有者の 0g0-id `sub`）と一致することを要求し、不一致は **403**（JSON-RPC エラー `-32001`、`error: "forbidden"`）で拒否する。

- `OWNER_SUB` が**未設定・空の場合は全員を拒否**する（fail closed）。設定忘れで公開状態にはならない。
- 配送は `OWNER_SUB` の購読にのみ行う。制限導入前に作られた他人の購読レコードが残っていても配送されない。
- `initialize` / `server/discover` / `ping` / `tools/list` / `events/list` と保護リソースメタデータは従来どおり（依頼データを含まないため）。
- 本番の `OWNER_SUB` の値はデプロイ時に API／ダッシュボードで設定する。リポジトリ内の `wrangler.toml` にはプレースホルダのみを置く。

### クライアント登録（ChatGPT 側の接続に必要）

- **DCR（動的登録）**: 0g0-id の `POST /api/register`（RFC 7591）。ChatGPT のような MCP クライアントが公開クライアント（`token_endpoint_auth_method: "none"` ＋ PKCE S256）として自己登録できる。redirect URI は https 必須（localhost の http は開発用に許可）。初期アクセストークンは不要。
- **管理登録**: 0g0-id の管理 API／管理画面から通常のクライアント（サービス）として事前登録してもよい。
- どちらの経路でも、認可の関門は「0g0-id のログイン画面で所有者本人がサインインすること」。登録できただけではトークンは発行されない。

### 発火 API（/trigger）の認証は OAuth とは別

- `/trigger` は従来どおり管理キー（`TRIGGER_KEY`）でのみ認証する機械間 API で、OAuth フローには組み込まない。送信者の本人性は「キー所持」によってのみ担保され、payload 内のフィールドでは決めない。実際、読み取るフィールドは `text`、`topic`、`request_id` のホワイトリストのみで、`status` や `callback_url`、`deliver_to` のような追加フィールドは無視される（テストで担保）。IdP のアクセストークンを /trigger のキー代わりに使うこともできない（テストで担保）。
- Webhook の `whsec_` 署名は「この配送が本サーバーから来たこと」の検証であり、元の依頼者の本人確認とは別のもの。この区別はコードコメントにも明記した。
- 届いた `text` は外部入力（信頼できないデータ）として扱う。payload には受信側の権限や安全制約を変えるフィールドを一切含めない（スキーマは従来どおり `request_id` / `text` / `topic` / `created_at` のみ）。

### 逆方向（Muse への依頼）— 1.3.0 で追加

`kick` が dots を起こすのと対に、dots や外部送信者から **Muse（ユーザーのもう一方のエージェント）へ依頼を届ける**経路。Muse 側に着信経路がない（Tailscale クライアントは外向き専用で、ランタイムへの直接呼び出しもない）ため、こちらも「サーバーに依頼を溜めて受信側が取りに来る」形を取る。依頼レコードは dots 向けとは別キースペース（`creq:`）に保存し、状態は `pending → acknowledged → completed`（共通の rank マージ）。

- **Webhook 受付 `POST /claude-hook`**: Standard Webhooks の HMAC 署名（`CLAUDE_HOOK_SECRET`、タイムスタンプ許容 ±5分）で認証する。webhook を直接 POST できる送信者（ユーザーの PC 上の Hermes、スクリプト等）向け。本文は `{text, topic?, request_id?}` で、重複排除は /trigger と同じ put-if-absent。
- **ツール `kick_claude`**: dots は任意の webhook を POST できないため、同じ登録を MCP ツールでも行えるようにしたもの。所有者制限の対象で、スコープ `claude:kick` が必要。
- **Muse 側の取り込み**: Muse のポーラーは秘密情報を扱えないため、件数だけを返す公開エンドポイント `GET /claude-inbox/signal`（`{pending: n}` のみ。ID・本文は含まない）を見て起きるかどうかを決める。本文の取得と状態更新は管理キー（`TRIGGER_KEY`）の `GET /claude-inbox` / `POST /claude-inbox/status` で行う。
- 届いた `text` は Muse にとって外部入力（信頼できないデータ）であり、dots が受ける依頼と同じ扱いにする。受信側の権限を広げるフィールドは持たない。

### request_id の重複排除と配送セマンティクス

- `/trigger` に呼び出し側が `request_id` を指定できる（形式: 英数字と `._:-`、最大128文字）。作成は Durable Object 内で原子的な put-if-absent で行うため、再送・同時到着でもレコードは1つしか作られず、二重配送は起きない。重複時は既存レコードの状態を `deduplicated: true` で返す。`request_id` を省略した場合は従来どおりサーバーが採番する。
- 配送そのものも（依頼 × 購読）の粒度で冪等（1.4.0〜）。各ペアについて、POST の前に Durable Object 内の永続台帳（キー `dlv:<requestId>`、購読ID → 状態のマップ）で claim し、結果を settle（`delivered` / `failed`）する。既に `delivered` のペアと、別の配送が実行中（claim のリース 45 秒以内）のペアは POST せずスキップする。判定は Worker のメモリではなく Durable Object のストレージに置くため、Worker の再起動や呼び出し側の再接続をまたいでも効く。
- 依頼が `pending` のまま重複 `/trigger` が来た場合（初回の応答が呼び出し側に届かなかった、初回配送が途中で死んだ、全試行が失敗した等）は、台帳で未配送のペアだけを再配送する（再駆動）。台帳が `delivered` なのにレコードへの結果マージだけが失われた場合は、再 POST せずレコードの状態だけを `delivered` に整合させる。claim だけが残ってリース切れになったペア（配送プロセスが settle 前に死んだ痕跡）は、再駆動時に引き継いで再試行する。この場合、初回の POST が受信側に届いていた可能性は排除できないため、最終防衛線は従来どおり決定的な `eventId`（`webhook-id`）による受信側の重複排除になる。
- Webhook の 2xx は「受信確認」であって「作業完了」ではない。完了は従来どおり `update_request_status` の `completed` で表す。配送リトライでは `eventId`（依頼ID＋購読IDから決定的に生成）を変えないため、受信側でも重複排除できる。各試行では署名タイムスタンプを更新する。受信側は署名検証に加え、タイムスタンプの許容範囲（Standard Webhooks の作法では5分程度）と `eventId` の重複チェックでリプレイに備えること。
- 依頼レコードへの変更はすべて Durable Object 内で最新レコードへのフィールド単位マージとして直列化して行う（作成は put-if-absent、配送結果は配送履歴の追記＋状態の前進のみ、状態更新は状態の前進＋メモの追記のみ）。Worker 側で読んだ古いスナップショットを丸ごと書き戻す経路はないため、配送と状態更新が並行しても、配送結果・状態・メモのいずれも競合で消えることはない。

### 環境変数・シークレット（名前のみ。値はリポジトリに書かない）

| 名前 | 種別 | 用途 |
|---|---|---|
| `TRIGGER_KEY` | シークレット（設定済み） | `POST /trigger` と `/claude-inbox` 管理エンドポイントのキー |
| `CLAUDE_HOOK_SECRET` | シークレット（要設定） | `POST /claude-hook`（逆方向 webhook 受付）の `whsec_` HMAC 秘密 |
| `OWNER_SUB` | 平文変数（要設定） | 所有者の 0g0-id `sub`。下記「所有者制限」参照。**本番値はデプロイ時に設定し、リポジトリには書かない**（`wrangler.toml` の値はプレースホルダ） |
| `IDP_ISSUER` | 平文変数（任意） | 認可サーバーの issuer。既定 `https://id.0g0.xyz` |
| `JWKS_URI` | 平文変数（任意） | JWKS の取得先。既定 `<IDP_ISSUER>/.well-known/jwks.json` |
| `RESOURCE_URI` | 平文変数（任意） | audience の期待値。既定は自オリジン + `/mcp`。0g0-id 側の登録 URI と一致させること |
| `TEST_ECHO` / `TEST_ECHO_SECRET` | 平文変数（テスト専用、本番では設定しない） | 署名検証エコー `POST /test-echo` の有効化と使い捨て秘密 |

内蔵認可サーバー方式で使っていた `OWNER_PASSWORD_HASH` / `AUTH_SECRET` は廃止した（本 Worker はログインもセッションもトークン発行もしない）。

### 運用・失効手順

- 個別トークンの失効: アクセストークンは 0g0-id の発行ポリシーで短命（15分）。リフレッシュトークンの失効は 0g0-id の `POST /api/token/revoke` で行う。
- クライアントの締め出し: 0g0-id 側で該当クライアント（サービス）を削除する。以後の認可・更新ができなくなる。
- 購読の締め出し: 購読は principal（`sub`）単位で保存されているため、対象ユーザーの購読レコードをストレージから削除すれば配送が止まる。
- 鍵ローテーション: 0g0-id 側で署名鍵を差し替えても、JWKS の再取得で自動追従する（未知 `kid` 検出時）。

### 検証方法

- 自動テスト（ローカル、合成データのみ、本番に触れない）: `npm install` のあと `npm test`（`test/auth.test.mjs` 21件＋`test/claude-inbox.test.mjs` 13件＋`test/delivery-dedup.test.mjs` 6件）。Miniflare 上で実 Worker を起動し、合成 ES256 鍵ペアで署名した 0g0-id 形式 JWT とモック JWKS（outboundService で配信）を使い、メタデータ（`authorization_servers` が 0g0-id を指すこと、内蔵 AS のエンドポイントが 404 であること）、無認証 401、不透明トークンの拒否、有効トークンでの接続→購読→署名付き配送→状態照合→解除の通し、署名不正・ペイロード改ざん・期限切れ・誤 `iss`・誤 `aud` の拒否、スコープ不足 403、別 principal による解除の無効化、未認証発火（IdP トークン流用含む）の拒否、`request_id` 重複の単一配送、payload による状態上書きの不可、鍵ローテーションへの追従、改ざん Webhook の拒否、kick スキーマ互換を確認する。セキュリティレビュー対応として、**所有者以外の正規トークン（全スコープ）での購読・照合・更新・解除の拒否と配送の所有者限定、`OWNER_SUB` 未設定時の fail closed、IPv6 プライベートリテラル（loopback／ULA／link-local／IPv4-mapped）の拒否、配送中に届いた状態更新が配送後の保存で巻き戻らないこと、配送と状態・メモ更新を並行に走らせても両方向の競合で配送結果・状態・メモが消えないこと、配送台帳による二重 POST の抑止（失敗した配送の再送が一度だけ再駆動されること、配送中の重複発火でも1回しか届かないこと、結果マージが失われても再 POST せず状態だけが整合すること、死んだ配送の claim 残りを引き継げること、重複排除の状態が Worker 再起動をまたいで保持されること）**の回帰テストも含む。GitHub Actions（`.github/workflows/ci.yml`）でも push / pull_request のたびに同じテストスイートを実行する。
- デプロイ後の実機確認: 保護リソースメタデータが 200 で `authorization_servers` に 0g0-id が入ること、無認証の `initialize` が 401 + `WWW-Authenticate` になること、ChatGPT の接続で 0g0-id のログイン画面に遷移し、認可後に `kick` の購読が作れること。

## 発火方法（管理用）

`POST /trigger` に管理キーで依頼テキストを送ると、依頼を保存し、アクティブな全購読へ即配送する。

```bash
KEY=$(cat ~/workspace/goals/reason-network/hidden_files/dots-events-trigger-key.txt)
curl -X POST https://dots-events.0g0.xyz/trigger \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $KEY" \
  -d '{"text":"依頼の本文","topic":"任意のトピック"}'
```

- 管理キーは Worker のシークレット `TRIGGER_KEY` と上記ファイルにのみ保存（値はこの README やログには書かない）。
- レスポンスは `request_id`、状態、一致した購読数、配送成功数、購読ごとの結果（秘密情報は含まない）。
- リクエストボディに `request_id` を含めると、その ID で冪等になる（再送しても二重に作られず、二重配送も起きない。詳細は「認証（OAuth 2.1）」内の重複排除の節）。

## dots 側の接続手順（未実施・dots 側の操作待ち）

前提として「認証（OAuth 2.1）＞前提・依存関係」の 0g0-id 側の準備（PR マージ・デプロイ・リソース登録）が完了していること。ガイドの手順に沿って dots／ユーザーが実施する:

1. プラグインとしてこの MCP サーバー（`https://dots-events.0g0.xyz/mcp`）を接続する。認証が必要なサーバーとして認識されると、0g0-id のログイン画面へ遷移するので、所有者アカウントでサインインして認可する（クライアント登録は DCR で自動に行われる想定。うまくいかない場合は 0g0-id の管理画面で事前登録する）。
2. MCP を再スキャンし、ツール2種とイベント `kick` がプラグイン画面に並ぶことを確認する。
3. Work チャット（または dots）で、`kick` イベントの購読と、届いたときの処理（例：依頼内容を確認し、`list_pending_requests` で照合して、着手時に `update_request_status` で `acknowledged`、終わったら `completed` を返す）を指示する。
4. こちらから `/trigger` でテスト依頼を送り、dots が起きて反応することを確認する。

## 検証結果（2026-11-06 実施済み）

- `initialize` / `server/discover` / `events/list` / `tools/list` がガイドの例示どおりの形で返ることを curl で確認。
- 署名アルゴリズムは Standard Webhooks 公式テストベクタと完全一致を事前確認。
- 署名を検証する独立エコー（別 Worker、検証後に削除済み）を使い、購読→チャレンジ検証→発火→署名付き配送（200）→`acknowledged`→`completed`→解除→配送停止、までの全ライフサイクルを実地で確認。
- 異常系も確認：管理キーなし発火 401／secret 形式不正 `-32602`／未知イベント `-32602`／http コールバック `-32015 (not_https)`／到達不能コールバック `-32015 (challenge_failed)`。
- 本番構成（テスト用変数を除いた最終ビルド）でもヘルス・各メソッド・発火（購読0件）のスモークテストを実施済み。ストレージには自己検証の完了済み依頼レコードが3件残っている（未完了一覧には出ない）。

### OAuth 対応の検証（2026-11-06、ローカル自動テスト）

- 初版（内蔵認可サーバー方式）: Miniflare 上の自動テスト12件合格。その後、方式変更に伴いテストも作り替えた。
- 現行（0g0-id 方式）: `test/auth.test.mjs` の **21件が全件合格**（内容は「認証（OAuth 2.1）＞検証方法」参照。うち5件はセキュリティレビュー指摘への回帰テスト）。0g0-id はモック JWKS ＋合成鍵で模擬し、本番 IdP・本番サーバーにはアクセスしていない。
- 本番に対して行った確認は読み取りのみ: 無認証の `initialize` / `events/list` / `tools/list` が成功すること（＝現行本番はオープンな原初ビルド）、保護リソースメタデータが 404 であることを確認済み。本番での購読作成・削除・発火は行っていない。
- 未実施: 前提（0g0-id 側 PR・登録）が揃った後の、ChatGPT 実機での認可フローと購読認識の確認。

## 制限・未確認事項

- **認証（OAuth 2.1）は実装済みだが未デプロイ**（このブランチ／PR の状態）。本番はまだ認証なしの原初ビルドで稼働しており、購読の principal は固定値 `anonymous`。有効化には本 PR のデプロイに加えて、0g0-id 側の前提（PR マージ・デプロイ・マイグレーション・リソース登録）が必要。デプロイ後は認証導入前の `anonymous` 購読には配送されなくなるため、dots 側は再購読が必要。
- 本方式は 0g0-id の RFC 8707 実装に依存する。0g0-id 側 PR が未マージの間は、audience 束縛つきトークンは発行できない。
- 0g0-id は CIMD（Client ID Metadata Documents）未対応で、クライアント登録は DCR と管理登録のみ。ChatGPT の接続形態が CIMD を必須とする場合は、0g0-id 側に追加実装が要る。
- ChatGPT 側でイベント購読先として認識されない問題と OAuth の有無の因果は未確定。OAuth 実装はその切り分け材料の1つであり、デプロイ後の実機確認で別途判断する。
- **購読と実配信の dots 側テストは未実施**（上記「接続手順」は dots 側の操作が必要なため）。ここまでで確認できているのはサーバー側の仕様準拠と自己検証まで。
- SSRF 対策は「HTTPS 必須＋プライベートIPリテラル等の拒否」まで。ガイドが求める「名前解決して検証済みアドレスへ接続」は Workers の fetch では実現できず、部分準拠。
- Worker から自分自身の URL への fetch は Cloudflare の制限で失敗する（自己検証で確認）。実運用のコールバックは ChatGPT 側の URL なので影響しない。
- イベントの replay（cursor）は非対応：`cursor` は常に `null`。配送断の間に起きた依頼はプロトコル上は復旧できないが、依頼レコード自体は残るため `list_pending_requests` で照合して拾える。
- テスト用に `worker.js` 内に `POST /test-echo`（`TEST_ECHO=1` のときだけ有効な署名検証エコー）と、その使い捨てフィクスチャ [echo-test-worker.js](sandbox://workspace/dots-kick-events/echo-test-worker.js) が残っている。本番では `TEST_ECHO` を設定していないため無効（404 を確認済み）。
