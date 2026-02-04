# Troubleshooting

## ETL produces no results

- Check `watchlist.json` terms
- Confirm network access to data sources

## GitHub Action fails to push

- On forks: scheduled pushes may be restricted; run locally or adjust permissions.

## Verify

- Run `python etl.py --min-year <year>` to broaden scan window
