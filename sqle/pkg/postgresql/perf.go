package postgresql

type DynPerformancePgColumns struct {
	SQLFullText    string  `json:"sql_fulltext"`
	Executions     float64 `json:"executions"`
	ElapsedTime    float64 `json:"elapsed_time"`
	DiskReads      float64 `json:"disk_reads"`
	BufferGets     float64 `json:"buffer_gets"`
	UserIOWaitTime float64 `json:"user_io_wait_time"`
}

const (
	DynPerformanceViewPgTpl = `
	select
		pss.query as sql_fulltext,
		sum ( pss.calls ) as executions,
		sum ( pss.total_exec_time ) as elapsed_time,
		sum ( pss.shared_blks_read ) as disk_reads,
		sum ( pss.shared_blks_hit ) as buffer_gets,
		sum ( pss.blk_read_time ) as user_io_wait_time 
	from
		pg_stat_statements pss
		join pg_database pd on pss.dbid = pd.oid 
	where
		pss.calls > 0 
		and query <> '<insufficient privilege>'
		and pd.datname = %v 
	group by pss.query 
	order by %v desc limit %v
	`
	DynPerformanceViewPgSQLColumnExecutions     = "executions"
	DynPerformanceViewPgSQLColumnElapsedTime    = "elapsed_time"
	DynPerformanceViewPgSQLColumnDiskReads      = "disk_reads"
	DynPerformanceViewPgSQLColumnBufferGets     = "buffer_gets"
	DynPerformanceViewPgSQLColumnUserIOWaitTime = "user_io_wait_time"
)
