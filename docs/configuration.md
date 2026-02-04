# Configuration

## watchlist.json

Schema:

```json
{
  "vendors": ["microsoft", "apache"],
  "products": ["log4j", "chrome"]
}
```

Matching behavior:

- Case-insensitive
- Vendor/product substring matching against `containers.cna.affected[]`

## Verify

- Update `watchlist.json`
- Run `python etl.py`
- Confirm new matches appear in `data/radar_data.json`
