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
3. コールバックURLは HTTPS 必須。localhost／プライベートIPリテラル等を拒否（拒否時は `-32015`）。
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

## 認証（OAuth 2.1）

MCP 認可仕様（OAuth 2.1 ベース）に準拠し、`/mcp` は保護リソースとして認証必須にした。認可サーバーは同一 Worker・同一オリジンに置く最小構成で、外部 IdP の新規契約や追加の認証情報は使わない。

### 方式の選択理由

- 前提: このサーバーのリソース所有者は1人（所有者本人）で、利用クライアントは ChatGPT（dots）だけ。複数ユーザーや組織向けの汎用 IdP は過剰。
- 外部 IdP（Auth0 / Clerk / Cloudflare Access 等）: テナント作成と認証情報の発行・設定が別途必要で、本変更の範囲外。将来ユーザー数が増えたら、保護リソース側（この Worker のトークン検証）はそのままに、認可サーバーだけ外部 IdP へ差し替え可能（メタデータの `authorization_servers` を変えるだけ）。
- GitHub OAuth 等の素の OAuth 2.0: RFC 8414 メタデータ、DCR、`resource` パラメータによる audience 束縛を満たさず、MCP クライアントのディスカバリと噛み合わない。
- 同一オリジン内蔵の認可サーバー: MCP 仕様自体が「認可サーバーはリソースサーバーと同一主体でホストしてよい」と認める構成。実装は標準部品のみ（後述）に絞り、独自暗号や独自フローは作っていない。

### 実装した要素

| 要素 | 内容 |
|---|---|
| 保護リソースメタデータ (RFC 9728) | `GET /.well-known/oauth-protected-resource` と `/.well-known/oauth-protected-resource/mcp`。`resource` は MCP エンドポイント URL、`authorization_servers` は自オリジン |
| 認可サーバーメタデータ (RFC 8414) | `GET /.well-known/oauth-authorization-server`（`/.well-known/openid-configuration` でも同じ文書を返す）。`code_challenge_methods_supported: ["S256"]`、`authorization_response_iss_parameter_supported: true` を広告 |
| 動的クライアント登録 (RFC 7591) | `POST /oauth/register`。公開クライアント（`token_endpoint_auth_method: "none"`）のみ。redirect URI は https 必須（localhost の http のみ開発用に許可） |
| 認可フロー | Authorization Code + PKCE（S256 必須、plain は拒否）。所有者がパスワードでログインし、同意画面でクライアント名・スコープ・戻り先を確認して許可する。認可応答には RFC 9207 の `iss` を常に付ける（成功・エラーとも） |
| トークン発行 | `POST /oauth/token`。認可コードは単一使用（原子的に取得・削除されるため、PKCE 検証に失敗した交換でも消費される）・有効期限10分。アクセストークン1時間、リフレッシュトークン30日（ローテーション式: 使用時に旧トークンを無効化し再利用を検出） |
| 失効 (RFC 7009) | `POST /oauth/revoke`。アクセストークン／リフレッシュトークンを個別に失効できる |
| トークン形式 | 不透明（opaque）トークン。保存時は SHA-256 ハッシュをキーにするため、ストレージ漏洩がそのまま資格情報漏洩にならない。検証はリクエストごとに issuer・audience（= このサーバーの resource）・有効期限・種別（access / refresh の混用防止）を確認 |
| 所有者ログイン | パスワードの SHA-256 ハッシュを Worker シークレット `OWNER_PASSWORD_HASH` に保持し、定数時間比較で照合。ログインセッションは `AUTH_SECRET` で HMAC 署名した Cookie（HttpOnly / Secure / SameSite=Lax、30分） |

### スコープと認可

| スコープ | 許可される操作 |
|---|---|
| `events:read` | `events/list` |
| `events:subscribe` | `events/subscribe`、`events/unsubscribe` |
| `requests:read` | `list_pending_requests` |
| `requests:update` | `update_request_status` |

- トークンがない・不正・期限切れの `/mcp` 呼び出しは **401** と `WWW-Authenticate: Bearer resource_metadata="…"、scope="…"` を返す。スコープ不足は **403**（単一リクエスト時）と step-up 用の `WWW-Authenticate` を返す（バッチ内では該当メッセージだけ JSON-RPC エラー `-32003`）。
- 購読はトークンの principal に結び付く。別 principal が同じ（URL・名前・引数）で解除しようとしても、購読ID自体が異なるため所有者の購読には届かない（レコード側でも principal 一致を確認する二重防御）。配送対象は認証済み principal の購読のみで、認証導入前の `anonymous` 購読（自己検証用データ）には配送しない。
- クライアント登録自体は誰でも可能だが、トークンは「所有者のログイン＋同意」を経ないと発行されないため、登録だけで権限は得られない。

### 発火 API（/trigger）の認証は OAuth とは別

- `/trigger` は従来どおり管理キー（`TRIGGER_KEY`）でのみ認証する機械間 API で、OAuth フローには組み込まない。送信者の本人性は「キー所持」によってのみ担保され、payload 内のフィールドでは決めない。実際、読み取るフィールドは `text`、`topic`、`request_id` のホワイトリストのみで、`status` や `callback_url`、`deliver_to` のような追加フィールドは無視される（テストで担保）。
- Webhook の `whsec_` 署名は「この配送が本サーバーから来たこと」の検証であり、元の依頼者の本人確認とは別のもの。この区別はコードコメントにも明記した。
- 届いた `text` は外部入力（信頼できないデータ）として扱う。payload には受信側の権限や安全制約を変えるフィールドを一切含めない（スキーマは従来どおり `request_id` / `text` / `topic` / `created_at` のみ）。

### request_id の重複排除と配送セマンティクス

- `/trigger` に呼び出し側が `request_id` を指定できる（形式: 英数字と `._:-`、最大128文字）。作成は Durable Object 内で原子的な put-if-absent で行うため、再送・同時到着でもレコードは1つしか作られず、二重配送は起きない。重複時は既存レコードの状態を `deduplicated: true` で返す。`request_id` を省略した場合は従来どおりサーバーが採番する。
- Webhook の 2xx は「受信確認」であって「作業完了」ではない。完了は従来どおり `update_request_status` の `completed` で表す。配送リトライでは `eventId`（依頼ID＋購読IDから決定的に生成）を変えないため、受信側でも重複排除できる。各試行では署名タイムスタンプを更新する。受信側は署名検証に加え、タイムスタンプの許容範囲（Standard Webhooks の作法では5分程度）と `eventId` の重複チェックでリプレイに備えること。

### 環境変数・シークレット（名前のみ。値はリポジトリに書かない）

| 名前 | 種別 | 用途 |
|---|---|---|
| `TRIGGER_KEY` | シークレット（設定済み） | `POST /trigger` の管理キー |
| `OWNER_PASSWORD_HASH` | シークレット（要設定） | 所有者ログイン用パスワードの SHA-256 ハッシュ（16進小文字）。例: `printf %s '決めたパスワード' \| sha256sum` で計算して設定する |
| `AUTH_SECRET` | シークレット（要設定） | セッション Cookie の HMAC 鍵。例: `openssl rand -hex 32` で生成して設定する |
| `TEST_ECHO` / `TEST_ECHO_SECRET` | 平文変数（テスト専用、本番では設定しない） | 署名検証エコー `POST /test-echo` の有効化と使い捨て秘密 |

`OWNER_PASSWORD_HASH` と `AUTH_SECRET` が未設定の間、`/oauth/*` は 503 を返し、`/mcp` は認証を通過できない（安全側に倒れる）。デプロイと同時に両シークレットを設定すること。

### 運用・失効手順

- 個別トークンの失効: `POST /oauth/revoke` に `token` と `client_id` を送る。
- クライアントの締め出し: ストレージの `client:<client_id>` レコードを削除すると、その client_id では新規認可ができなくなる（既存トークンは期限切れか個別失効まで有効）。
- 所有者パスワードの変更: `OWNER_PASSWORD_HASH` を新しいハッシュに差し替える。既存セッションも止めたい場合は `AUTH_SECRET` も差し替える（セッション全失効。発行済みトークンには影響しない）。
- 全トークンの一括失効: ストレージの `token:` プレフィックスのレコードを全削除する。

### 検証方法

- 自動テスト（ローカル、合成データのみ、本番に触れない）: `npm install` のあと `npm test`。Miniflare 上で実 Worker を起動し、メタデータ検証、無認証 401、認可フロー（誤パスワード拒否・PKCE・コード単一使用）、期限切れ／誤 audience／誤 issuer／refresh 混用の拒否、スコープ不足 403、別 principal による解除の無効化、未認証発火 401、`request_id` 重複（順次・同時）の単一配送、payload による状態・配送先の上書き不可、改ざん Webhook の拒否、リフレッシュローテーションと失効、kick スキーマ互換までを確認する。
- デプロイ後の目視確認: メタデータ2種が 200 で返ること、無認証の `initialize` が 401 + `WWW-Authenticate` になること、ChatGPT の接続で OAuth フロー（ログイン→同意）が始まること。

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

ガイドの手順に沿って dots／ユーザーが実施する:

1. プラグインとしてこの MCP サーバー（`https://dots-events.0g0.xyz/mcp`）を接続する。認証が必要なサーバーとして認識されると OAuth フローが始まるので、所有者パスワードでログインし、同意画面で許可する（事前に `OWNER_PASSWORD_HASH` と `AUTH_SECRET` の設定と、本変更のデプロイが必要）。
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

- Miniflare 上で実 Worker を起動する自動テスト12件（`test/oauth.test.mjs`、`npm test` で実行）を作成し、全件合格。内容は「認証（OAuth 2.1）＞検証方法」に記載のとおり（認可フロー実走、異常系トークン、所有者バインディング、重複排除、改ざん Webhook、ローテーション・失効、kick 互換）。
- 受信側（ChatGPT コールバック）は Miniflare の outboundService で模擬し、Standard Webhooks 署名を Node の crypto で独立に検証した上でチャレンジ応答・配送記録を行った（接続→購読→発火→配送→状態照合までの合成データでの通し検証を含む）。
- 本番に対して行った確認は読み取りのみ: 無認証の `initialize` / `events/list` / `tools/list` が成功すること（＝現行本番はオープン）、保護リソースメタデータが 404 であること（＝ OAuth 未デプロイ）を確認済み。本番での購読作成・削除・発火は行っていない。
- 未実施: デプロイ後の ChatGPT 実機での OAuth フローと購読認識の確認（デプロイとシークレット設定が前提のため、本変更のマージ後に所有者の承認を得て実施する）。

## 制限・未確認事項

- **認証（OAuth 2.1）は実装済みだが未デプロイ**（このブランチ／PR の状態）。本番はまだオープンで、購読IDの principal は固定値 `anonymous`。有効化には `OWNER_PASSWORD_HASH` と `AUTH_SECRET` のシークレット設定と同時のデプロイが必要（手順は「認証（OAuth 2.1）」参照）。デプロイ後は認証導入前の `anonymous` 購読には配送されなくなるため、dots 側は再購読が必要。
- ChatGPT 側でイベント購読先として認識されない問題と OAuth の有無の因果は未確定。OAuth 実装はその切り分け材料の1つであり、デプロイ後の実機確認で別途判断する。
- クライアント登録は CIMD（Client ID Metadata Documents）未対応で、DCR と事前登録のみ。ChatGPT が CIMD を必須とする接続形態では追加実装が要る。
- 認可サーバー側のレート制限は未実装（単一所有者前提）。ログイン試行の総当たり対策はプラットフォーム側の防御に依存する。
- 認可コードは PKCE 検証に失敗した交換でも消費される（単一使用を原子的に担保するための設計上の選択）。
- **購読と実配信の dots 側テストは未実施**（上記「接続手順」は dots 側の操作が必要なため）。ここまでで確認できているのはサーバー側の仕様準拠と自己検証まで。
- SSRF 対策は「HTTPS 必須＋プライベートIPリテラル等の拒否」まで。ガイドが求める「名前解決して検証済みアドレスへ接続」は Workers の fetch では実現できず、部分準拠。
- Worker から自分自身の URL への fetch は Cloudflare の制限で失敗する（自己検証で確認）。実運用のコールバックは ChatGPT 側の URL なので影響しない。
- イベントの replay（cursor）は非対応：`cursor` は常に `null`。配送断の間に起きた依頼はプロトコル上は復旧できないが、依頼レコード自体は残るため `list_pending_requests` で照合して拾える。
- テスト用に `worker.js` 内に `POST /test-echo`（`TEST_ECHO=1` のときだけ有効な署名検証エコー）と、その使い捨てフィクスチャ [echo-test-worker.js](sandbox://workspace/dots-kick-events/echo-test-worker.js) が残っている。本番では `TEST_ECHO` を設定していないため無効（404 を確認済み）。
