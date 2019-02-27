package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
	"gopkg.in/ini.v1"
)

const defaultConfigFile = "/etc/grafana/staging/grafana.ini"
const dashboardQuery = `
SELECT
  dd.id as id,
  dd.title as title,
  df.title as folder,
  o.name as organization,
  dd.data as data,

  dd.created as created_date,
  uc.name as created_name,
  uc.login as created_login,
  uc.email as created_email,

  dd.updated as updated_date,
  uu.name as updated_name,
  uu.login as updated_login,
  uu.email as updated_email

FROM public.dashboard dd
LEFT JOIN public.dashboard df ON dd.folder_id = df.id
LEFT JOIN public.user uc ON dd.created_by = uc.id
LEFT JOIN public.user uu ON dd.updated_by = uu.id
LEFT JOIN public.org o ON dd.org_id = o.id
WHERE dd.is_folder = false
ORDER BY folder, title
`

type Target struct {
	RefId  string `json:"refId"`
	Target string `json:"target"`
	Expr   string `json:"expr"`
	Query  string `json:"query"`
}

func (t *Target) GetQuery() string {
	if t.Target != "" {
		return t.Target
	} else if t.Query != "" {
		return t.Query
	} else if t.Expr != "" {
		return t.Expr
	} else {
		return "Unknown"
	}
}

type Panel struct {
	ID         int64  `json:"id"`
	Title      string `json:"title"`
	Type       string `json:"type"`
	Datasource string `json:"datasource"`
	Targets    []Target
}

type Row struct {
	Title  string  `json:"title"`
	Panels []Panel `json:"panels"`
}

type DashboardData struct {
	ID          int64    `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Panels      []Panel  `json:"panels"`
	Rows        []Row
}

func (d *DashboardData) GetPanels() []Panel {
	if len(d.Rows) == 0 {
		return d.Panels
	} else {
		panels := make([]Panel, len(d.Panels))
		panels = append(panels, d.Panels...)
		for _, row := range d.Rows {
			for _, panel := range row.Panels {
				panels = append(panels, panel)
			}
		}
		return panels
	}
}

type Dashboard struct {
	Id           sql.NullInt64
	Title        sql.NullString
	Folder       sql.NullString
	Organization sql.NullString

	CreatedDate  sql.NullString
	CreatedName  sql.NullString
	CreatedLogin sql.NullString
	CreatedEmail sql.NullString

	UpdatedDate  sql.NullString
	UpdatedName  sql.NullString
	UpdatedLogin sql.NullString
	UpdatedEmail sql.NullString

	Json sql.NullString
	Data DashboardData
}

func (d *Dashboard) GetName() string {
	if d.Folder.String == "" {
		return d.Title.String
	} else {
		return fmt.Sprintf("%s/%s", d.Folder.String, d.Title.String)
	}
}

func main() {
	var configFile string
	var listenHost string
	var listenPort int

	flag.StringVar(&configFile, "config", defaultConfigFile, "The path to the Grafana config INI file.")
	flag.StringVar(&listenHost, "host", "0.0.0.0", "Bind to this host.")
	flag.IntVar(&listenPort, "port", 80, "Bind to this port number.")
	flag.Parse()

	config, err := ini.Load(configFile)
	if err != nil {
		panic(err)
	}

	dbHostPort := config.Section("database").Key("host").String()
	dbName := config.Section("database").Key("name").String()
	dbUser := config.Section("database").Key("user").String()
	dbPassword := config.Section("database").Key("password").String()
	dbURL := config.Section("database").Key("url").String()
	dbSSLMode := config.Section("database").Key("ssl_mode").String()

	dbHostPortArray := strings.Split(dbHostPort, ":")
	dbHost := dbHostPortArray[0]
	dbPort := dbHostPortArray[1]

	if dbURL == "" {
		if dbHost == "" {
			dbHost = "127.0.0.1"
		}
		if dbPort == "" {
			dbHost = "5432"
		}
		if dbName == "" {
			dbName = "grafana"
		}
		if dbUser == "" {
			dbUser = "grafana"
		}
		if dbSSLMode == "" {
			dbSSLMode = "disable"
		}
	}

	if dbURL == "" {
		dbURL = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)
	}

	dbConnection, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}

	err = dbConnection.Ping()
	if err != nil {
		panic(err)
	}

	rows, err := dbConnection.Query(dashboardQuery)
	if err != nil {
		panic(err)
	}

	var dashboard Dashboard

	type SearchRecord struct {
		DashboardId   int64    `json:"dashboardId"`
		DashboardUid  string   `json:"dashboardUid"`
		DashboardTitle string  `json:"dashboardTitle"`
		DashboardSlug string   `json:"dashboardSlug"`
		DashboardTags []string `json:"dashboardTags"`
		FolderId      int64    `json:"folderId"`
		FolderTitle   string   `json:"folderTitle"`
		PanelId       int64    `json:"panelId"`
		PanelTitle    string   `json:"panelTitle"`
		TargetRefId   string   `json:"targetRefId"`
		TargetQuery   string   `json:"targetName"`
		Datasource    string   `json:"datasource"`
		AlertId       int64    `json:"alertId"`
		AlertName     string   `json:"alert"`
		Url           string   `json:"url"`
	}

	var searchResult []SearchRecord

	for rows.Next() {
		dashboard = Dashboard{}
		err = rows.Scan(
			&dashboard.Id,
			&dashboard.Title,
			&dashboard.Folder,
			&dashboard.Organization,
			&dashboard.Json,

			&dashboard.CreatedDate,
			&dashboard.CreatedName,
			&dashboard.CreatedLogin,
			&dashboard.CreatedEmail,

			&dashboard.UpdatedDate,
			&dashboard.UpdatedName,
			&dashboard.UpdatedLogin,
			&dashboard.UpdatedEmail,
		)
		if err != nil {
			panic(err)
		}

		dashboardData := DashboardData{}
		err := json.Unmarshal([]byte(dashboard.Json.String), &dashboardData)
		if err != nil {
			panic(err)
		}

		var record SearchRecord
		for _, panel := range dashboardData.GetPanels() {
			for _, target := range panel.Targets {
				record = SearchRecord{}
				record.DashboardId = dashboardData.Id
				record.DashboardUid = dashboardData.Uid
				record.DashboardSlug= dashboardData.Slug
				record.DashboardTitle= dashboardData.Title
				record.DashboardTags = dashboardData.Tags
				record.FolderId = dashboardData.FolderId
				record.FolderTitle = dashboardData.FolderTitle
				record.PanelId = dashboardData.PanelId
				record.PanelTitle = dashboardData.PanelTitle
				record.TargetRefId = target.RefId
				record.TargetQuery = target.GetQuery()
				record.Datasource = panel.Datasource
			}

		}

	}

	rows.Close()
	dbConnection.Close()

	for _, dashboard := range dashboards {
		fmt.Printf("%s (%s)\n", dashboard.GetName(), dashboard.Data.Description)
		for _, panel := range dashboard.Data.GetPanels() {
			fmt.Printf("  * %s (%s) %s\n", panel.Title, panel.Type, panel.Datasource)
			for _, target := range panel.Targets {
				fmt.Printf("    => %s: %s\n", target.RefID, target.GetTarget())
			}
		}
	}

	fmt.Printf("Total: %d\n", len(dashboards))
}
