package login

import (
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/registry"
	"github.com/grafana/grafana/pkg/services/quota"
)

func init() {
	registry.RegisterService(&LoginService{})
}

var (
	logger = log.New("login.ext_user")
)

type LoginService struct {
	Bus          bus.Bus             `inject:""`
	QuotaService *quota.QuotaService `inject:""`
}

func (ls *LoginService) Init() error {
	ls.Bus.AddHandler(ls.UpsertUser)

	return nil
}

func (ls *LoginService) UpsertUser(cmd *m.UpsertUserCommand) error {
	extUser := cmd.ExternalUser

	userQuery := &m.GetUserByAuthInfoQuery{
		AuthModule: extUser.AuthModule,
		AuthId:     extUser.AuthId,
		UserId:     extUser.UserId,
		Email:      extUser.Email,
		Login:      extUser.Login,
	}

	err := bus.Dispatch(userQuery)
	if err != m.ErrUserNotFound && err != nil {
		return err
	}

	if err != nil {
		if !cmd.SignupAllowed {
			log.Warn("Not allowing %s login, user not found in internal user database and allow signup = false", extUser.AuthModule)
			return ErrInvalidCredentials
		}

		limitReached, err := ls.QuotaService.QuotaReached(cmd.ReqContext, "user")
		if err != nil {
			log.Warn("Error getting user quota. error: %v", err)
			return ErrGettingUserQuota
		}
		if limitReached {
			return ErrUsersQuotaReached
		}

		cmd.Result, err = createUser(extUser)
		if err != nil {
			return err
		}

		if extUser.AuthModule != "" && extUser.AuthId != "" {
			cmd2 := &m.SetAuthInfoCommand{
				UserId:     cmd.Result.Id,
				AuthModule: extUser.AuthModule,
				AuthId:     extUser.AuthId,
			}
			if err := ls.Bus.Dispatch(cmd2); err != nil {
				return err
			}
		}

	} else {
		cmd.Result = userQuery.Result

		err = updateUser(cmd.Result, extUser)
		if err != nil {
			return err
		}
	}

	err = syncOrgRoles(cmd.Result, extUser)
	if err != nil {
		return err
	}

	err = syncOrgTeams(cmd.Result, extUser)
	if err != nil {
		return err
	}

	// Sync isGrafanaAdmin permission
	if extUser.IsGrafanaAdmin != nil && *extUser.IsGrafanaAdmin != cmd.Result.IsAdmin {
		if err := ls.Bus.Dispatch(&m.UpdateUserPermissionsCommand{UserId: cmd.Result.Id, IsGrafanaAdmin: *extUser.IsGrafanaAdmin}); err != nil {
			return err
		}
	}

	err = ls.Bus.Dispatch(&m.SyncTeamsCommand{
		User:         cmd.Result,
		ExternalUser: extUser,
	})

	if err == bus.ErrHandlerNotFound {
		return nil
	}

	return err
}

func createUser(extUser *m.ExternalUserInfo) (*m.User, error) {
	cmd := &m.CreateUserCommand{
		Login:        extUser.Login,
		Email:        extUser.Email,
		Name:         extUser.Name,
		SkipOrgSetup: len(extUser.OrgRoles) > 0,
	}

	if err := bus.Dispatch(cmd); err != nil {
		return nil, err
	}

	return &cmd.Result, nil
}

func updateUser(user *m.User, extUser *m.ExternalUserInfo) error {
	// sync user info
	updateCmd := &m.UpdateUserCommand{
		UserId: user.Id,
	}

	needsUpdate := false
	if extUser.Login != "" && extUser.Login != user.Login {
		updateCmd.Login = extUser.Login
		user.Login = extUser.Login
		needsUpdate = true
	}

	if extUser.Email != "" && extUser.Email != user.Email {
		updateCmd.Email = extUser.Email
		user.Email = extUser.Email
		needsUpdate = true
	}

	if extUser.Name != "" && extUser.Name != user.Name {
		updateCmd.Name = extUser.Name
		user.Name = extUser.Name
		needsUpdate = true
	}

	if !needsUpdate {
		return nil
	}

	logger.Debug("Syncing user info", "id", user.Id, "update", updateCmd)
	return bus.Dispatch(updateCmd)
}

func syncOrgTeams(user *m.User, extUser *m.ExternalUserInfo) error {
	// don't sync org teams if none are specified
	if len(extUser.OrgTeams) == 0 {
		return nil
	}

	logger.Debug("Syncing OrgTeams", "login", user.Login, "external", extUser.OrgTeams)

	// query existing teams of a user
	teamsQuery := &m.GetTeamsByUserQuery{OrgId: user.OrgId, UserId: user.Id}
	if err := bus.Dispatch(teamsQuery); err != nil {
		log.Error(3, "Could not query the list of user's teams", err)
	}

	// find team id which are no longer present in external user data and should be removed
	deleteTeamIds := []int64{}
	for _, existingUserTeam := range teamsQuery.Result {
		userTeamStillAssigned := false
		for _, extTeam := range extUser.OrgTeams[user.OrgId] {
			if existingUserTeam.Name == extTeam {
				userTeamStillAssigned = true
			}
		}
		if !userTeamStillAssigned {
			deleteTeamIds = append(deleteTeamIds, existingUserTeam.Id)
		}
	}
	logger.Debug("Syncing OrgTeams", "login", user.Login, "deleteTeamIds", deleteTeamIds)

	// go through the found ids and remove them from user's team membership
	for _, deleteTeamId := range deleteTeamIds {
		err := bus.Dispatch(&m.RemoveTeamMemberCommand{OrgId: user.OrgId, TeamId: deleteTeamId, UserId: user.Id})
		if err != nil {
			log.Error(3, "Could not remove user from a team", err)
		}
	}

	// find the list of team names which are present in the external user data, but are not assigned to the user yet
	assignTeamNames := []string{}
	for _, extTeam := range extUser.OrgTeams[user.OrgId] {
		extTeamAlreadyAssigned := false
		for _, existingUserTeam := range teamsQuery.Result {
			if existingUserTeam.Name == extTeam {
				extTeamAlreadyAssigned = true
			}
		}
		if !extTeamAlreadyAssigned {
			assignTeamNames = append(assignTeamNames, extTeam)
		}
	}
	logger.Debug("Syncing OrgTeams", "login", user.Login, "assignTeamNames", assignTeamNames)

	// search every external team name and get the list of team ids if the external team is found
	assignTeamIds := []int64{}
	for _, assignTeamName := range assignTeamNames {
		teamSearchQuery := &m.SearchTeamsQuery{
			OrgId: user.OrgId,
			Name:  assignTeamName,
		}
		err := bus.Dispatch(teamSearchQuery)
		if err != nil {
			log.Error(3, "Could not remove user from a team", err)
		}
		if teamSearchQuery.Result.TotalCount > 0 {
			assignTeamIds = append(assignTeamIds, teamSearchQuery.Result.Teams[0].Id)
		}
	}
	logger.Debug("Syncing OrgTeams", "login", user.Login, "assignTeamIds", assignTeamIds)

	// go though the list of team ids and add them to the user's membership
	for _, assignTeamId := range assignTeamIds {
		err := bus.Dispatch(&m.AddTeamMemberCommand{OrgId: user.OrgId, TeamId: assignTeamId, UserId: user.Id, External: true})
		if err != nil {
			log.Error(3, "Could not add user to a team", err)
		}
	}

	return nil
}

func syncOrgRoles(user *m.User, extUser *m.ExternalUserInfo) error {
	// don't sync org roles if none are specified
	if len(extUser.OrgRoles) == 0 {
		return nil
	}

	logger.Debug("Syncing OrgRoles", "login", user.Login, "external", extUser.OrgRoles)

	orgsQuery := &m.GetUserOrgListQuery{UserId: user.Id}
	if err := bus.Dispatch(orgsQuery); err != nil {
		return err
	}

	handledOrgIds := map[int64]bool{}
	deleteOrgIds := []int64{}

	// update existing org roles
	for _, org := range orgsQuery.Result {
		handledOrgIds[org.OrgId] = true

		if extUser.OrgRoles[org.OrgId] == "" {
			deleteOrgIds = append(deleteOrgIds, org.OrgId)
		} else if extUser.OrgRoles[org.OrgId] != org.Role {
			// update role
			cmd := &m.UpdateOrgUserCommand{OrgId: org.OrgId, UserId: user.Id, Role: extUser.OrgRoles[org.OrgId]}
			if err := bus.Dispatch(cmd); err != nil {
				return err
			}
		}
	}

	// add any new org roles
	for orgId, orgRole := range extUser.OrgRoles {
		if _, exists := handledOrgIds[orgId]; exists {
			continue
		}

		// add role
		cmd := &m.AddOrgUserCommand{UserId: user.Id, Role: orgRole, OrgId: orgId}
		err := bus.Dispatch(cmd)
		if err != nil && err != m.ErrOrgNotFound {
			return err
		}
	}

	// delete any removed org roles
	for _, orgId := range deleteOrgIds {
		cmd := &m.RemoveOrgUserCommand{OrgId: orgId, UserId: user.Id}
		if err := bus.Dispatch(cmd); err != nil {
			return err
		}
	}

	// update user's default org if needed
	if _, ok := extUser.OrgRoles[user.OrgId]; !ok {
		for orgId := range extUser.OrgRoles {
			user.OrgId = orgId
			break
		}

		return bus.Dispatch(&m.SetUsingOrgCommand{
			UserId: user.Id,
			OrgId:  user.OrgId,
		})
	}

	return nil
}
