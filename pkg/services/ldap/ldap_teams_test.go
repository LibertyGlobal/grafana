package ldap

import (
	"github.com/inconshreveable/log15"
	"testing"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/ldap.v3"
)

func Test_LDAP_Teams_Methods(t *testing.T) {
	logger = log.NewWithLevel("test_log", log15.LvlDebug)

	Convey("serializeUsers() Teams and Roles", t, func() {
		Convey("Role selection", func() {
			server := &Server{
				Config: &ServerConfig{
					Attr: AttributeMap{
						Username: "username",
						Name:     "name",
						MemberOf: "memberof",
						Email:    "email",
					},
					SearchBaseDNs: []string{"BaseDNHere"},
				},
				Connection: &MockConnection{},
				log: logger,
			}

			server.Config.Groups = []*GroupToOrgRole{
				{
					OrgId: 1,
					GroupDN: "team1",
					TeamName: "Team-A",
					OrgRole: models.ROLE_VIEWER,
				},
				{
					OrgId: 1,
					GroupDN: "team2",
					TeamName: "Team-B",
					OrgRole: models.ROLE_EDITOR,
				},
				{
					OrgId: 1,
					GroupDN: "team3",
					TeamName: "Team-C",
					OrgRole: models.ROLE_EDITOR,
				},
				{
					OrgId: 1,
					GroupDN: "admin",
					TeamName: "Admin",
					OrgRole: models.ROLE_ADMIN,
				},
			}

			entry := ldap.Entry{
				DN: "dn",
				Attributes: []*ldap.EntryAttribute{
					{Name: "username", Values: []string{"test_user"}},
					{Name: "surname", Values: []string{"User"}},
					{Name: "email", Values: []string{"user@test.com"}},
					{Name: "name", Values: []string{"Test"}},
					{Name: "memberof", Values: []string{"team1", "team3"}},
				},
			}
			users := []*ldap.Entry{&entry}

			result, err := server.serializeUsers(users)
			//for _, resultUser := range result {
			//	t.Log("Resulting user",
			//		"name", resultUser.Name,
			//		"roles", resultUser.OrgRoles,
			//		"teams", resultUser.OrgTeams,
			//		)
			//}

			So(err, ShouldBeNil)
			So(result[0].Login, ShouldEqual, "test_user")
			So(result[0].Email, ShouldEqual, "user@test.com")
			So(result[0].Groups, ShouldResemble, []string{"team1", "team3"})
			So(result[0].OrgTeams[1], ShouldResemble, []string{"Team-A", "Team-C"})
			So(result[0].OrgRoles[1], ShouldResemble, models.ROLE_EDITOR)
		})

	})
}
