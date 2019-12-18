package social

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/grafana/grafana/pkg/models"

	"golang.org/x/oauth2"
)

type SocialRizzoOAuth struct {
	*SocialBase
	allowedDomains []string
	apiUrl         string
	allowSignup    bool
	roleSupport    bool
	roleAttribute  string
	deniedRole     string
	viewerRole     string
	editorRole     string
	adminRole      string
	defaultRole    string
	groupSupport   bool
	groupBasic     string
	groupViewer    string
	groupEditor    string
}

func (s *SocialRizzoOAuth) Type() int {
	return int(models.RIZZO)
}

func (s *SocialRizzoOAuth) IsEmailAllowed(email string) bool {
	return isEmailAllowed(email, s.allowedDomains)
}

func (s *SocialRizzoOAuth) IsSignupAllowed() bool {
	return s.allowSignup
}

type RizzoUserInfoJson struct {
	Id        string      `json:"id"`
	Email     string      `json:"email"`
	RizzoId   string      `json:"rizzo_id"`
	OracleId  string      `json:"oracle_id"`
	FirstName string      `json:"first_name"`
	LastName  string      `json:"last_name"`
	Access    interface{} `json:"access"`
}

func (s *SocialRizzoOAuth) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data RizzoUserInfoJson
	var err error

	response, err := HttpGet(client, s.apiUrl)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

	s.log.Debug(fmt.Sprintf("Received the UserInfo JSON: %s", string(response.Body)))
	err = json.Unmarshal(response.Body, &data)
	if err != nil {
		return nil, fmt.Errorf("Error decoding user info JSON: %s Got: %s", err, string(response.Body))
	}

	email := s.extractEmail(&data)
	login := s.extractLogin(&data, email)
	name := s.extractName(&data, login)

	userInfo := &BasicUserInfo{
		Name:  name,
		Login: login,
		Email: email,
	}

	if s.roleSupport || s.groupSupport {
		rizzoRole := s.extractRole(&data, login, email)
		if s.roleSupport {
			userInfo.Role = s.rizzoRoleToGrafanaRole(rizzoRole, login, email)
		}
		if s.groupSupport {
			userInfo.Groups = s.rizzoRoleToGrafanaGroups(rizzoRole, login, email)
		}
	}

	return userInfo, nil
}

func (s *SocialRizzoOAuth) extractEmail(data *RizzoUserInfoJson) string {
	if data.Email != "" {
		return data.Email
	}

	return ""
}

func (s *SocialRizzoOAuth) extractLogin(data *RizzoUserInfoJson, email string) string {
	if data.RizzoId != "" {
		return data.RizzoId
	}

	if data.OracleId != "" {
		return data.OracleId
	}

	if data.Id != "" {
		return data.Id
	}

	return email
}

func (s *SocialRizzoOAuth) extractName(data *RizzoUserInfoJson, login string) string {
	if data.FirstName != "" || data.LastName != "" {
		return strings.Title(strings.ToLower(data.FirstName)) + " " + strings.Title(strings.ToLower(data.LastName))
	}

	return login
}

func (s *SocialRizzoOAuth) extractRole(data *RizzoUserInfoJson, login string, email string) string {
	accessMap, ok := data.Access.(map[string]interface{})
	if !ok {
		s.log.Warn(fmt.Sprintf("User '%s' (%s) has an incorrect access section, assuming the default role and basic group", login, email))
		return s.defaultRole
	}
	roleInterface, ok := accessMap[s.roleAttribute]
	if !ok {
		s.log.Warn(fmt.Sprintf("User '%s' (%s) has no access attribute in the access section, assuming the default role and basic group", login, email))
		return s.defaultRole
	}
	roleString, ok := roleInterface.(string)
	if !ok {
		s.log.Warn(fmt.Sprintf("User '%s' (%s) has an incorrect access attribute in the access section, assuming the default role and basic group", login, email))
		return s.defaultRole
	}
	s.log.Debug(fmt.Sprintf("User '%s' (%s) has the role: '%s'", login, email, roleString))
	return roleString
}

func (s *SocialRizzoOAuth) rizzoRoleToGrafanaRole(rizzoRole string, login string, email string) string {
	switch rizzoRole {
	case s.deniedRole:
		return string(models.ROLE_VIEWER)
	case s.viewerRole:
		return string(models.ROLE_VIEWER)
	case s.editorRole:
		return string(models.ROLE_EDITOR)
	case s.adminRole:
		return string(models.ROLE_ADMIN)
	default:
		s.log.Warn(fmt.Sprintf("User '%s' (%s) has an unknown role '%s', assuming the viewer role", login, email, rizzoRole))
		return string(models.ROLE_VIEWER)
	}
}

func (s *SocialRizzoOAuth) rizzoRoleToGrafanaGroups(rizzoRole string, login string, email string) []string {
	switch rizzoRole {
	case s.deniedRole:
		return []string{s.groupBasic}
	case s.viewerRole:
		return []string{s.groupBasic, s.groupViewer}
	case s.editorRole:
		return []string{s.groupBasic, s.groupViewer, s.groupEditor}
	case s.adminRole:
		return []string{s.groupBasic, s.groupViewer, s.groupEditor}
	default:
		s.log.Warn(fmt.Sprintf("User '%s' (%s) has an unknown role '%s', assuming the basic group", login, email, rizzoRole))
		return []string{s.groupBasic}
	}
}
