package common

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/actiontech/sqle/sqle/cmd/scannerd/scanners"
	"github.com/actiontech/sqle/sqle/pkg/scanner"
)

func Upload(ctx context.Context, sqls []scanners.SQL, c *scanner.Client, apName string) error {
	// key=fingerPrint val=count
	counterMap := make(map[string]uint, len(sqls))

	nodeList := make([]scanners.SQL, 0, len(sqls))
	for _, node := range sqls {
		counterMap[node.Fingerprint]++
		if counterMap[node.Fingerprint] <= 1 {
			nodeList = append(nodeList, node)
		}
	}

	reqBody := make([]*scanner.AuditPlanSQLReq, 0, len(nodeList))
	now := time.Now().Format(time.RFC3339)
	for _, sql := range nodeList {
		reqBody = append(reqBody, &scanner.AuditPlanSQLReq{
			Fingerprint:          sql.Fingerprint,
			Counter:              fmt.Sprintf("%v", counterMap[sql.Fingerprint]),
			LastReceiveText:      sql.RawText,
			LastReceiveTimestamp: now,
		})
	}

	return c.UploadReq(scanner.FullUpload, apName, reqBody)
}

func Audit(c *scanner.Client, apName string) error {
	reportID, err := c.TriggerAuditReq(apName)
	if err != nil {
		return err
	}
	return c.GetAuditReportReq(apName, reportID)
}

func UploadForDmSlowLog(ctx context.Context, sqls []scanners.SQL, c *scanner.Client, apName string) error {
	var sqlListReq []*scanner.AuditPlanSQLReq
	auditPlanSqlMap := make(map[string]*scanner.AuditPlanSQLReq, 0)
	now := time.Now()

	for _, node := range sqls {
		key := node.Fingerprint
		if sqlReq, ok := auditPlanSqlMap[key]; ok {
			atoI, err := strconv.Atoi(sqlReq.Counter)
			if err != nil {
				return err
			}

			sqlReq.Fingerprint = node.Fingerprint
			tMax := *sqlReq.QueryTimeMax
			if node.QueryTime > tMax {
				tMax = node.QueryTime
			}
			tAvg := (*sqlReq.QueryTimeAvg*float64(atoI) + node.QueryTime) / float64(atoI+1)
			sqlReq.QueryTimeMax = &tMax
			sqlReq.QueryTimeAvg = &tAvg
			sqlReq.Counter = strconv.Itoa(atoI + 1)
			sqlReq.LastReceiveText = node.RawText
			sqlReq.LastReceiveTimestamp = now.Format(time.RFC3339)
			sqlReq.DBUser = node.DBUser
			sqlReq.Schema = node.Schema
		} else {
			auditSqlReq := &scanner.AuditPlanSQLReq{
				Fingerprint:          node.Fingerprint,
				LastReceiveText:      node.RawText,
				LastReceiveTimestamp: now.Format(time.RFC3339),
				Counter:              "1",
				QueryTimeAvg:         &node.QueryTime,
				QueryTimeMax:         &node.QueryTime,
				FirstQueryAt:         node.QueryAt,
				DBUser:               node.DBUser,
				Schema:               node.Schema,
			}
			sqlListReq = append(sqlListReq, auditSqlReq)
		}
	}
	return c.UploadReq(scanner.PartialUpload, apName, sqlListReq)
}
