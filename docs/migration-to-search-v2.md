## Object Search API V2

Starting with the `0.12.0` release of the REST gateway, an Object Search API V2 is available:

```
/v2/objects/{containerId}/search
```

### Key Differences Between V1 and V2

The primary difference between the `V1` and `V2` versions lies in how they handle _pagination_:

- **V1**
    - Uses `offset` and `limit` parameters.
    - Implements classical paging behavior.
    - `limit` has a maximum value of **10,000**.

- **V2**
    - Uses `cursor` and `limit` parameters.
    - Implements infinite scroll behavior.
    - `limit` has a maximum value of **1,000**.

### How to Use Search API V2

The general flow for using Search V2 is as follows:

1. Make a search request with an empty `cursor`.
2. Check the returned `cursor`:

- If the `cursor` is **empty**, you have retrieved all objects matching the filter.
- If the `cursor` is **not empty**, use it in the next request to retrieve the next batch of results.

### Performance Considerations

- For optimal performance, the **first filter** should be the most **restrictive**.
- The **maximum number of attributes** you can filter by is **7**.

### Additional Notes

- Unlike V1, the results from a V2 search are **sorted by the `Timestamp` attribute in ascending order**.
