# FortiAuthenticator API collections

MAC device and group membership fetches reuse an HTTP session for their pages.
Each fetch owns and closes its session, including when a page fails. Sessions and
cookies are not shared between profiles or collection fetches. Single API calls
also close their session when complete. No automatic retries are added for reads
or deletes.

The client reads responses in chunks and applies these policy limits:

| Policy constant in twn_toolkit/fortiauthenticator.py | Default | Scope |
| --- | --- | --- |
| MAX_RESPONSE_BYTES | 8 MiB | One response, after decompression |
| MAX_COLLECTION_BYTES | 64 MiB | All response bodies in one collection fetch |
| MAX_COLLECTION_OBJECTS | 100,000 | All returned objects in one collection fetch |
| MAX_PAGINATION_PAGES | 1,000 | Pages in one collection fetch |

These are centralized code tuning points, not profile UI settings. Adjust them
with the deployment's available memory and expected inventory size in mind.
Decoded Python objects use additional memory; byte limits are not process RSS
limits. The existing profile timeout still governs connection and read waits,
not the total collection duration or system DNS resolution.

An exceeded budget, malformed collection, repeating page link, or interrupted
request fails the fetch rather than returning partial results. Cleanup execution
requires a successful fresh inventory check before deleting selected records.
Large deployments that hit a limit receive an error; results are not silently
truncated.

Pagination links must remain on the configured origin. HTTP redirects are rejected
before reading their response body; configure the final appliance URL in the
profile if the appliance redirects its API. This also prevents redirected requests
from bypassing response budgets or replaying a mutation.

Connection reuse requires appliance keep-alive support. The session consumes each
bounded response or closes it on failure, following the
[Requests session and streaming lifecycle](https://requests.readthedocs.io/en/latest/user/advanced/#body-content-workflow).
