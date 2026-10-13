# Convert ClickBench hits_<n>.parquet to NDJSON with the same SELECT bench-matrix
# uses (cmd/bench/load.go convertFile), through the worktree's ADBC DuckDB driver.
#   mix run --no-start scripts/prep/convert.exs <parquet> <out.ndjson>
[src, dst] = System.argv()
Application.load(:smolquery); Application.ensure_all_started(:adbc)
{:ok, db} = Adbc.Database.start_link(driver: :duckdb, version: Application.fetch_env!(:smolquery, :duckdb_driver_version))
{:ok, conn} = Adbc.Connection.start_link(database: db)
sql = """
COPY (SELECT * REPLACE (
    make_timestamp(EventTime * 1000000) AS EventTime,
    make_timestamp(ClientEventTime * 1000000) AS ClientEventTime,
    make_timestamp(LocalEventTime * 1000000) AS LocalEventTime,
    DATE '1970-01-01' + EventDate::INTEGER AS EventDate)
  FROM read_parquet('#{src}', binary_as_string = true))
TO '#{dst}' (FORMAT json)
"""
{t, res} = :timer.tc(fn -> Adbc.Connection.query(conn, sql) end)
IO.inspect({res |> elem(0), t / 1.0e6}, label: "converted #{src}")
