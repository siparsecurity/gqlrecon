# GQLRecon

A GraphQL security fuzzer built by Sipar Security.

Covers introspection abuse detection, batching attack testing, depth and
complexity abuse, alias based rate limit bypass, and field level
authorization testing against GraphQL APIs.

## Status

Early development. Stage 1 (schema discovery) complete.

## Stages

1. Schema discovery via introspection, with wordlist fallback
2. Batching and alias abuse testing (planned)
3. Depth and complexity fuzzing (planned)
4. Field level authorization testing (planned)
5. Risk scoring and HTML report (planned)

## Usage

    cd stages
    python3 stage1_discovery.py --url https://target.com/graphql

## License

MIT
