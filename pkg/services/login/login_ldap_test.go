package login

import (
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/inconshreveable/log15"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/models"
)

func init()  {
	logger = log.NewWithLevel("test_log", log15.LvlDebug)
	logger.Debug("Test log init")
}

func Test_syncOrgTeams(t *testing.T) {
	user := createLDAPUser()
	externalUser := createLDAPExternalUser()

	bus.ClearBusHandlers()
	defer bus.ClearBusHandlers()

	bus.AddHandler("test", func(q *models.GetTeamsByUserQuery) error {
		q.Result = createLDAPUserTeamDTO()
		return nil
	})
	bus.AddHandler("test", func(q *models.SearchTeamsQuery) error {
		q.Result = createLDAPSearchTeamQueryResult(q.Name)
		return nil
	})

	bus.AddHandler("test", func(cmd *models.RemoveTeamMemberCommand) error {
		// Expect removal of the Team2 of the test_user
		require.Equal(t, int64(1), cmd.OrgId)
		require.Equal(t, int64(100), cmd.UserId)
		require.Equal(t, int64(12), cmd.TeamId)
		return nil
	})

	bus.AddHandler("test", func(cmd *models.AddTeamMemberCommand) error {
		// Expect addition of the Team3 of the test_user
		require.Equal(t, int64(1), cmd.OrgId)
		require.Equal(t, int64(100), cmd.UserId)
		require.Equal(t, int64(13), cmd.TeamId)
		return nil
	})

	err := syncOrgTeams(&user, &externalUser)

	require.NoError(t, err)
}

func createLDAPUser() models.User {
	user := models.User{
		Id: int64(100),
		OrgId: int64(1),
		Login: "test_user",

	}
	return user
}

func createLDAPUserTeamDTO() []*models.TeamDTO {
	result := []*models.TeamDTO{
		{
			Id: int64(11),
			OrgId: int64(1),
			Name:  "Team-A",
		},
		{
			Id: int64(12),
			OrgId: int64(1),
			Name:  "Team-B",
		},
	}
	return result
}

func createLDAPSearchTeamQueryResult(teamName string) models.SearchTeamQueryResult {

	result := models.SearchTeamQueryResult{
		Teams: make([]*models.TeamDTO, 0),
		TotalCount: 1,
	}

	if teamName == "Team-A" {
		result.Teams = []*models.TeamDTO{
			{
				Id: 11,
				OrgId: 1,
				Name: "Team-A",
			},
		}
	} else if teamName == "Team-B" {
		result.Teams = []*models.TeamDTO{
			{
				Id: 12,
				OrgId: 1,
				Name: "Team-B",
			},
		}
	} else if teamName == "Team-C" {
		result.Teams = []*models.TeamDTO{
			{
				Id: 13,
				OrgId: 1,
				Name: "Team-C",
			},
		}
	}

	return result
}

func createLDAPExternalUser() models.ExternalUserInfo {
	externalUser := models.ExternalUserInfo{
		AuthModule: "ldap",
		OrgRoles: map[int64]models.RoleType{
			1: models.ROLE_VIEWER,
		},
		OrgTeams: map[int64][]string{
			1: {"Team-A", "Team-C"},
		},
	}

	return externalUser
}
