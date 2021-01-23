package login

import (
	"errors"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/registry"
	"github.com/grafana/grafana/pkg/services/quota"
)

func init() {
	registry.RegisterService(&LoginService{})
}

var (
	logger = log.New("login.ext_user")
)

type TeamSyncFunc func(user *models.User, externalUser *models.ExternalUserInfo) error

type LoginService struct {
	Bus          bus.Bus             `inject:""`
	QuotaService *quota.QuotaService `inject:""`
	TeamSync     TeamSyncFunc
}

func (ls *LoginService) Init() error {
	ls.Bus.AddHandler(ls.UpsertUser)

	return nil
}

// UpsertUser updates an existing user, or if it doesn't exist, inserts a new one.
func (ls *LoginService) UpsertUser(cmd *models.UpsertUserCommand) error {
	extUser := cmd.ExternalUser

	userQuery := &models.GetUserByAuthInfoQuery{
		AuthModule: extUser.AuthModule,
		AuthId:     extUser.AuthId,
		UserId:     extUser.UserId,
		Email:      extUser.Email,
		Login:      extUser.Login,
	}
	if err := bus.Dispatch(userQuery); err != nil {
		if !errors.Is(err, models.ErrUserNotFound) {
			return err
		}
		if !cmd.SignupAllowed {
			log.Warnf("Not allowing %s login, user not found in internal user database and allow signup = false", extUser.AuthModule)
			return ErrInvalidCredentials
		}

		limitReached, err := ls.QuotaService.QuotaReached(cmd.ReqContext, "user")
		if err != nil {
			log.Warnf("Error getting user quota. error: %v", err)
			return ErrGettingUserQuota
		}
		if limitReached {
			return ErrUsersQuotaReached
		}

		cmd.Result, err = createUser(extUser)
		if err != nil {
			return err
		}

		if extUser.AuthModule != "" {
			cmd2 := &models.SetAuthInfoCommand{
				UserId:     cmd.Result.Id,
				AuthModule: extUser.AuthModule,
				AuthId:     extUser.AuthId,
				OAuthToken: extUser.OAuthToken,
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

		// Always persist the latest token at log-in
		if extUser.AuthModule != "" && extUser.OAuthToken != nil {
			err = updateUserAuth(cmd.Result, extUser)
			if err != nil {
				return err
			}
		}

		if extUser.AuthModule == models.AuthModuleLDAP && userQuery.Result.IsDisabled {
			// Re-enable user when it found in LDAP
			if err := ls.Bus.Dispatch(&models.DisableUserCommand{UserId: cmd.Result.Id, IsDisabled: false}); err != nil {
				return err
			}
		}
	}

	if err := syncOrgRoles(cmd.Result, extUser); err != nil {
		return err
	}

	if err := syncOrgTeams(cmd.Result, extUser); err != nil {
		return err
	}

	// Sync isGrafanaAdmin permission
	if extUser.IsGrafanaAdmin != nil && *extUser.IsGrafanaAdmin != cmd.Result.IsAdmin {
		if err := ls.Bus.Dispatch(&models.UpdateUserPermissionsCommand{UserId: cmd.Result.Id, IsGrafanaAdmin: *extUser.IsGrafanaAdmin}); err != nil {
			return err
		}
	}

	if ls.TeamSync != nil {
		err := ls.TeamSync(cmd.Result, extUser)
		if err != nil {
			return err
		}
	}

	return nil
}

func createUser(extUser *models.ExternalUserInfo) (*models.User, error) {
	cmd := &models.CreateUserCommand{
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

func updateUser(user *models.User, extUser *models.ExternalUserInfo) error {
	// sync user info
	updateCmd := &models.UpdateUserCommand{
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

func updateUserAuth(user *models.User, extUser *models.ExternalUserInfo) error {
	updateCmd := &models.UpdateAuthInfoCommand{
		AuthModule: extUser.AuthModule,
		AuthId:     extUser.AuthId,
		UserId:     user.Id,
		OAuthToken: extUser.OAuthToken,
	}

	logger.Debug("Updating user_auth info", "user_id", user.Id)
	return bus.Dispatch(updateCmd)
}

func syncOrgRoles(user *models.User, extUser *models.ExternalUserInfo) error {
	// don't sync org roles if none is specified
	if len(extUser.OrgRoles) == 0 {
		logger.Debug("Not syncing organization roles since external user doesn't have any")
		return nil
	}

	logger.Debug("Syncing organization roles",
		"id", user.Id, "login", user.Login, "extOrgRoles", extUser.OrgRoles,
	)

	orgsQuery := &models.GetUserOrgListQuery{UserId: user.Id}
	if err := bus.Dispatch(orgsQuery); err != nil {
		return err
	}

	handledOrgIds := map[int64]bool{}
	deleteOrgIds := []int64{}

	// update existing org roles
	for _, org := range orgsQuery.Result {
		handledOrgIds[org.OrgId] = true

		extRole := extUser.OrgRoles[org.OrgId]
		if extRole == "" {
			deleteOrgIds = append(deleteOrgIds, org.OrgId)
		} else if extRole != org.Role {
			// update role
			cmd := &models.UpdateOrgUserCommand{OrgId: org.OrgId, UserId: user.Id, Role: extRole}
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
		cmd := &models.AddOrgUserCommand{UserId: user.Id, Role: orgRole, OrgId: orgId}
		err := bus.Dispatch(cmd)
		if err != nil && !errors.Is(err, models.ErrOrgNotFound) {
			return err
		}
	}

	// delete any removed org roles
	for _, orgId := range deleteOrgIds {
		logger.Debug("Removing user's organization membership as part of syncing with OAuth login",
			"userId", user.Id, "orgId", orgId)
		cmd := &models.RemoveOrgUserCommand{OrgId: orgId, UserId: user.Id}
		if err := bus.Dispatch(cmd); err != nil {
			if errors.Is(err, models.ErrLastOrgAdmin) {
				logger.Error(err.Error(), "userId", cmd.UserId, "orgId", cmd.OrgId)
				continue
			}

			return err
		}
	}

	// update user's default org if needed
	if _, ok := extUser.OrgRoles[user.OrgId]; !ok {
		for orgId := range extUser.OrgRoles {
			user.OrgId = orgId
			break
		}

		return bus.Dispatch(&models.SetUsingOrgCommand{
			UserId: user.Id,
			OrgId:  user.OrgId,
		})
	}

	return nil
}

func syncOrgTeams(user *models.User, extUser *models.ExternalUserInfo) error {
	// don't sync org teams if none are specified
	if len(extUser.OrgTeams[user.OrgId]) == 0 {
		logger.Debug("Not syncing organization teams since external user doesn't have any")
		return nil
	}

	logger.Debug("Syncing organization teams",
		"id", user.Id, "login", user.Login, "OrgTeams", extUser.OrgTeams[user.OrgId],
	)

	// query existing teams of a user
	teamsQuery := &models.GetTeamsByUserQuery{OrgId: user.OrgId, UserId: user.Id}
	if err := bus.Dispatch(teamsQuery); err != nil {
		logger.Error("Could not query the user's teams: " + err.Error(),
			"id", user.Id, "login", user.Login,
		)
		return err
	}

	// Compare the list of existing user's teams with the list of external user's teams
	// to find the team ids which are no longer present in external user's team list
	deleteTeamIds := make([]int64, 0)
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

	logger.Debug("Removing the user from the teams",
		"id", user.Id, "login", user.Login, "deleteTeamIds", deleteTeamIds,
	)

	// Go through the found team ids and remove them from user's team membership
	for _, deleteTeamId := range deleteTeamIds {
		err := bus.Dispatch(&models.RemoveTeamMemberCommand{
			OrgId:  user.OrgId,
			TeamId: deleteTeamId,
			UserId: user.Id,
		})
		if err != nil {
			logger.Error("Could not remove the user from the team: " + err.Error(),
				"id", user.Id, "login", user.Login, "teamId", deleteTeamId,
			)
			return nil
		}
	}

	// Find the list of team names which are present in the external user data,
	// but are not assigned to the existing user yet.
	assignTeamNames := make([]string, 0)
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

	logger.Debug("Resolving external team names",
		"id", user.Id, "login", user.Login, "assignTeamNames", assignTeamNames,
	)

	// Search every external team name and get the list of team ids for every external team found
	assignTeamIds := make([]int64, 0)
	for _, assignTeamName := range assignTeamNames {
		teamSearchQuery := &models.SearchTeamsQuery{
			OrgId: user.OrgId,
			Name:  assignTeamName,
		}
		err := bus.Dispatch(teamSearchQuery)
		if err != nil {
			logger.Error("Could not search for the team id: " + err.Error(),
				"teamName", assignTeamName,
			)
			return nil
		}
		if teamSearchQuery.Result.TotalCount > 0 {
			assignTeamIds = append(assignTeamIds, teamSearchQuery.Result.Teams[0].Id)
		}
	}

	logger.Debug("Assigning new teams to the user",
		"id", user.Id, "login", user.Login, "assignTeamIds", assignTeamIds,
	)

	// Go though the list of team ids and add them to the user's membership
	for _, assignTeamId := range assignTeamIds {
		err := bus.Dispatch(&models.AddTeamMemberCommand{
			OrgId:    user.OrgId,
			TeamId:   assignTeamId,
			UserId:   user.Id,
			External: true,
		})
		if err != nil {
			logger.Error("Could not assign the team to the user: " + err.Error(),
				"id", user.Id, "login", user.Login, "teamId", assignTeamId,
			)
			return nil
		}
	}

	return nil
}
