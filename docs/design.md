# Model and acceptance boundaries

The four inputs are immutable evidence, with checksums and full typed inventory in baseline.json. Normalization preserves Xray substring/full/root distinctions and IPv4/IPv6 networks. Only exact duplicates with the same type, action, priority and options are removed. Nested suffixes are reported and retained; no rule deletion crosses an action or priority boundary.

Friend snapshots have an unknown source date. Observed counts: 97 suffix, 23 process, one keyword proxy rule, and one direct suffix. New rules remain REVIEW, including all new processes. Comments about legal status are not evidence. Live providers are checked for changes but never silently replace reviewed snapshots.

Priorities: BLOCK 0, explicit policy 10, personal domain/IP 20, Windows process 30, opted-in provider 60, aggregate categories 80, DIRECT fallback 999. HAPP preserves its separate action-group order. Its compact GeoSite subtracts only proxy entries wholly covered by explicit personal DIRECT. Wider conflicting suffix/keyword/regex rules fail. Block categories retain the original security precedence.

Historical GeoSite has all 19 required categories. The friend's smaller candidate lacks ru-blocked and ru-available-only-inside, so it is rejected as a drop-in replacement. GeoIP required categories are private/direct/whitelist. Inventory compares categories/members/checksums, not just size.

Mihomo initializes custom GeoIP by checking a CN category. This source lacks CN; the PC output therefore uses category CIDRs converted to IP MRS. HAPP uses the compatible protobuf GeoIP at a verified pinned upstream URL. .dat, .mrs and classical YAML are separate formats. GeoSite subsetting preserves raw protobuf metadata/attributes except audited exclusions; binary files are not concatenated.

X/Twitter root/CDN rules include t.co, twimg.com, twtrdns.net, oauth, Periscope and TweetDeck. The actual twitter category is listed in twitter.json. Grok/xAI have a separate label. No new general CDN rule or gstatic.com is imported from the friend snapshot.

Base DNS and fake-ip filters are preserved. Optional DoH binds 127.0.0.1:1053, uses IP DoH for encrypted bootstrap, pins Yandex's hostname in hosts while retaining the TLS hostname, and defines proxy-server-nameserver/direct-nameserver. IPv6 stays disabled. Local .lan/.local/.home.arpa names return REFUSED in the optional variant to avoid a system-resolver loop or forwarding them to public resolvers; configure a known LAN resolver explicitly if required. Synthetic fake-IP destinations require domain mapping and never become LAN bypass. Actual DNS leakage and IPv6/TUN behavior require device tests.

Offline smoke databases are explicitly synthetic fixtures. Production requires actual verified binaries. Native tests use a reject mock node in an isolated directory and do not modify a subscription. Equivalent Xray configuration validates the actual GeoSite/GeoIP categories and regex. Native HAPP on iOS is unavailable here.

The Router profile is compiled independently with PROCESS-NAME removed and find-process-mode set to off. Domain suffixes, exact domains, regex/keyword matches, GeoSite expansions, IPv4/IPv6 and CIDR are preserved in their original order. Its local provider directory contains only the required process-free providers. Byte-identical PC/Router domain and IP files share one Release asset; a filename collision with different bytes still fails publication. Router is tested by the official Mihomo binary and separate golden routes, including a PC process that must have no effect on the router.

Optional Actions synchronization consumes only profiles whose SHA256 matches the latest published stable Release. A separate scoped API token is supplied through GitHub Secrets to the final workflow step. It updates the encoded YAML of two explicitly selected MIHOMO template UUIDs and merges only the HAPP routing response header. All other header/settings fields remain unchanged. Writes are read back; failures restore previous field values when no concurrent administrator edit intervenes. Template assignment to client subscriptions remains an explicit panel setting.
