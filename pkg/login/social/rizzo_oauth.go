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
	Id        string            `json:"id"`
	Email     string            `json:"email"`
	RizzoId   string            `json:"rizzo_id"`
	OracleId  string            `json:"oracle_id"`
	FirstName string            `json:"first_name"`
	LastName  string            `json:"last_name"`
	Access    map[string]string `json:"access"`
}

func (s *SocialRizzoOAuth) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data RizzoUserInfoJson
	var err error

	response, err := HttpGet(client, s.apiUrl)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

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

	if s.roleSupport {
		role, err := s.extractRole(&data, login, email, s.defaultRole)
		if err != nil {
			return nil, err
		}
		userInfo.Role = role
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

func (s *SocialRizzoOAuth) extractRole(data *RizzoUserInfoJson, login string, email string, defaultRole string) (string, error) {
	rizzoRole, found := data.Access[s.roleAttribute]
	if !(found && rizzoRole != "") {
		s.log.Debug(fmt.Sprintf("There is no Rizzo role in the access section for the user '%s' (%s) Using the default role '%s'", login, email, defaultRole), "rizzo_oauth")
		rizzoRole = defaultRole
	}

	switch rizzoRole {
	case s.deniedRole:
		return "", fmt.Errorf("User '%s' (%s) has the role '%s' and is not allowed to login into this system", login, email, rizzoRole)
	case s.viewerRole:
		return string(models.ROLE_VIEWER), nil
	case s.editorRole:
		return string(models.ROLE_EDITOR), nil
	case s.adminRole:
		return string(models.ROLE_ADMIN), nil
	default:
		return "", fmt.Errorf("User '%s' (%s) has an unknown role '%s'", login, email, rizzoRole)
	}
}
