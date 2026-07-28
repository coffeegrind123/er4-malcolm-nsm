# Driving every surface from the CLI

Everything in Dashboards Management, Data Administration and Settings & Setup is
reachable from a script. `tools/osapi` wraps the lot.

Nothing here is read-only: index patterns, saved objects, advanced settings,
workspaces, ISM policies, users and roles can all be created and modified.

## Three transports, because the surfaces genuinely differ

| | Reaches | Auth |
|---|---|---|
| `osapi osd` | Dashboards REST — saved objects, settings, workspaces | basic auth via nginx |
| `osapi es` | The whole OpenSearch REST API via the Dev Tools console proxy | basic auth via nginx |
| `osapi sec` | Security plugin admin API | **admin certificate**, executed inside the opensearch container |

The third exists because the security plugin's admin API does not accept a
password at all — it authenticates the client *certificate*
(`CN=opensearch-admin,OU=admin,O=Malcolm`). No amount of basic auth reaches it;
`malcolm_internal` gets a flat 403. `osapi sec` runs curl inside the container
where that cert lives.

> The server certificate's CN is `opensearch-node`, so verification against
> `localhost` fails and `-k` is required. Client-certificate auth is unaffected.

## Verified capability matrix

| Surface | Command | State |
|---|---|---|
| Index patterns | `osapi objects index-pattern` | 3 defined |
| Dashboards | `osapi objects dashboard` | 111 |
| Visualizations / saved searches | `osapi objects visualization` | ✓ |
| Advanced settings | `osapi settings get` / `set` | read + write |
| Workspaces | `osapi ws list` / `create` / `delete` | ✓ |
| Data sources | `osapi osd /api/saved_objects/_find?type=data-source` | plugin active; none configured (the local cluster is implicit) |
| Cluster / `_cat` / aliases / templates | `osapi es GET ...` | ✓ |
| ISM retention policies | `osapi ism list` / `add` / `apply` | read + write |
| Snapshots & repositories | `osapi es GET _snapshot` | ✓ |
| Notification channels | `osapi es GET _plugins/_notifications/configs` | ✓ |
| SQL | `osapi sql '...'` | ✓ |
| PPL | `osapi ppl '...'` | ✓ |
| Query insights | `osapi insights latency` | ✓ (path is `_insights/…`, **not** `_plugins/_query_insights/…`) |
| ML | `osapi es POST _plugins/_ml/models/_search '{...}'` | ✓ (requires a body; a bare GET returns 400) |
| Users / roles / role mappings / audit | `osapi sec GET ...` | full admin |

Also installed and reachable the same way: `alerting`, `anomaly-detection`,
`security-analytics`, `observability`, `reports-scheduler`, `sql`, `knn`,
`geospatial`, `flow-framework`, `search-relevance`.

Confirm at any time — and note that this listing is the *control* that
distinguishes "plugin absent" from "I used the wrong path":

```sh
tools/osapi es GET '_cat/plugins?format=json&h=component'
```

## PPL is usually the fastest way to ask a question

Hand-writing aggregation DSL is rarely worth it:

```sh
tools/osapi ppl 'source=arkime_sessions3-* | stats count() by event.dataset'
tools/osapi ppl 'source=arkime_sessions3-* | where event.dataset="dns" | stats count() by dns.host | sort - `count()` | head 20'
tools/osapi ppl 'source=arkime_sessions3-* | where source.ip="192.168.1.100" | stats count() by server.domain | sort - `count()` | head 20'
tools/osapi sql 'SELECT destination.ip, COUNT(*) c FROM arkime_sessions3-* GROUP BY destination.ip ORDER BY c DESC LIMIT 10'
```

Backtick-quote aggregate aliases like `` `count()` `` when sorting on them.

## Common operations

**Settings** — the time picker default is the usual cause of "there's no data":

```sh
tools/osapi settings get
tools/osapi settings set timepicker:timeDefaults '{"from":"now-24h","to":"now"}'
tools/osapi settings set theme:darkMode true
```

**Workspaces:**

```sh
tools/osapi ws list
tools/osapi ws create "Network Investigation" analytics
```

**Retention** — full-packet indices grow until the disk does not. The bundled
policy ages indices to read-only at 7d and deletes at 90d.

```sh
tools/osapi ism add malcolm-session-retention collector/ism-retention.json
tools/osapi es POST '_plugins/_ism/add/arkime_sessions3-260728' '{"policy_id":"malcolm-session-retention"}'
tools/osapi es GET '_plugins/_ism/explain/arkime_sessions3-*'
```

Three things that decide whether this actually works:

- **Check `INDEX_MANAGEMENT_ENABLED` first.** If Malcolm's own index management
  is on, adding this gives you two managers on the same indices. It ships
  `false`, so ISM is the only manager, but verify rather than assume.
- **The `ism_template` is what covers future indices.** Attaching a policy only
  affects indices that exist right now. Without the template, tomorrow's daily
  index is unmanaged and retention quietly stops working months later, which is
  exactly when nobody is looking.
- **The template pattern is `arkime_sessions3-2*`, not `-*`.** The wildcard also
  matches `arkime_sessions3-initial`, an empty index Arkime keeps as a template.
  Ageing that into a delete state is a surprise with no upside.

`state=(not yet evaluated)` right after attaching is normal — ISM runs on a
schedule (roughly every 30-48 minutes), it does not act on attach.

**Users and roles:**

```sh
tools/osapi sec GET _plugins/_security/api/internalusers
tools/osapi sec GET _plugins/_security/api/roles
tools/osapi sec PUT _plugins/_security/api/internalusers/analyst \
  '{"password":"...","backend_roles":["readall"],"description":"read-only analyst"}'
```

**Cluster health, and fixing a red one:**

```sh
tools/osapi es GET '_cluster/health?level=indices'
tools/osapi es GET '_cluster/allocation/explain?pretty'
tools/osapi es POST '_cluster/reroute?retry_failed=true'
```

If a shard reports `CorruptIndexException` on a single-node cluster there is no
replica to recover from and retrying cannot help — that data is already gone.
Check *what* the index holds before deleting it: Arkime's `arkime_history_v1-*`
is UI search history and is disposable, `arkime_sessions3-*` is your captured
data and is not.

## Saved objects

```sh
tools/osapi objects dashboard 100
tools/osapi objects index-pattern
tools/osapi osd '/api/saved_objects/dashboard/<id>'                     # read one
tools/osapi osd '/api/saved_objects/_export' -X POST -d '{"type":"dashboard"}' > dashboards.ndjson
tools/osapi osd '/api/saved_objects/_import?overwrite=true' -X POST \
  -H 'osd-xsrf:true' -F file=@dashboards.ndjson                          # restore
```

Export before editing anything you care about — `_import` overwrites by id.

## Anything not wrapped

The escape hatch reaches the raw APIs:

```sh
tools/osapi es  GET  '_cat/indices?v&s=store.size:desc'
tools/osapi es  PUT  'my-index/_settings' '{"index.number_of_replicas":0}'
tools/osapi osd '/api/status'
tools/osapi sec GET  '_plugins/_security/api/rolesmapping'
```

`osapi es` takes `METHOD PATH [BODY]`; the console proxy is always POSTed to and
the real method travels in the query string, which is why a bare
`curl -X GET .../console/proxy` does not behave as expected.
