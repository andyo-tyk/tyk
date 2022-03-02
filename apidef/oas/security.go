package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"
)

const (
	apiKey = "apiKey"
	oauth2 = "oauth2"

	header = "header"
	query  = "query"
	cookie = "cookie"
)

func (s *OAS) fillToken(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.AuthTokenType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillApiKeyScheme(&authConfig)

	token := &Token{}
	token.Enabled = api.UseStandardAuth
	token.AuthSources.Fill(authConfig)
	token.EnableClientCertificate = authConfig.UseCertificate
	if token.Signature == nil {
		token.Signature = &Signature{}
	}

	token.Signature.Fill(authConfig)
	if ShouldOmit(token.Signature) {
		token.Signature = nil
	}

	s.getTykSecuritySchemes()[authConfig.Name] = token

	if ShouldOmit(token) {
		delete(s.getTykSecuritySchemes(), authConfig.Name)
	}
}

func (s *OAS) extractTokenTo(api *apidef.APIDefinition, name string) {
	authConfig := apidef.AuthConfig{DisableHeader: true}

	if token := s.getTykTokenAuth(name); token != nil {
		api.UseStandardAuth = token.Enabled
		authConfig.UseCertificate = token.EnableClientCertificate
		token.AuthSources.ExtractTo(&authConfig)
		if token.Signature != nil {
			token.Signature.ExtractTo(&authConfig)
		}
	}

	s.extractApiKeySchemeTo(&authConfig, name)

	api.AuthConfigs[apidef.AuthTokenType] = authConfig
}

func (s *OAS) fillOAuth(api apidef.APIDefinition) {
	authConfig, ok := api.AuthConfigs[apidef.OAuthType]
	if !ok || authConfig.Name == "" {
		return
	}

	s.fillOauthScheme(api.Oauth2Meta.AllowedAccessTypes, authConfig.Name)

	oauth := &OAuth{}
	oauth.Enabled = api.UseOauth2
	oauth.AuthSources.Fill(authConfig)

	oauth.AllowedAuthorizeTypes = api.Oauth2Meta.AllowedAuthorizeTypes
	oauth.AuthLoginRedirect = api.Oauth2Meta.AuthorizeLoginRedirect

	if oauth.Notifications == nil {
		oauth.Notifications = &Notifications{}
	}

	oauth.Notifications.Fill(api.NotificationsDetails)
	if ShouldOmit(oauth.Notifications) {
		oauth.Notifications = nil
	}

	if ShouldOmit(oauth) {
		oauth = nil
	}

	s.getTykSecuritySchemes()[authConfig.Name] = oauth
}

func (s *OAS) extractOAuthTo(api *apidef.APIDefinition, name string) {
	authConfig := apidef.AuthConfig{Name: name}

	if oauth := s.getTykOAuth(name); oauth != nil {
		api.UseOauth2 = oauth.Enabled
		oauth.AuthSources.ExtractTo(&authConfig)
		api.Oauth2Meta.AllowedAuthorizeTypes = oauth.AllowedAuthorizeTypes
		api.Oauth2Meta.AuthorizeLoginRedirect = oauth.AuthLoginRedirect

		if oauth.Notifications != nil {
			oauth.Notifications.ExtractTo(&api.NotificationsDetails)
		}
	}

	s.extractOAuthSchemeTo(api, name)

	api.AuthConfigs[apidef.OAuthType] = authConfig
}

func (s *OAS) extractSecurityTo(api *apidef.APIDefinition) {
	if a := s.getTykAuthentication(); a != nil {
		api.UseKeylessAccess = !a.Enabled
		api.StripAuthData = a.StripAuthorizationData
		api.BaseIdentityProvidedBy = a.BaseIdentityProvider
	} else {
		api.UseKeylessAccess = true
	}

	if api.AuthConfigs == nil {
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
	}

	if len(s.Security) == 0 {
		return
	}

	for name := range s.Security[0] {
		switch s.Components.SecuritySchemes[name].Value.Type {
		case apiKey:
			s.extractTokenTo(api, name)
		case oauth2:
			s.extractOAuthTo(api, name)
		}
	}
}

func (s *OAS) fillSecurity(api apidef.APIDefinition) {
	a := s.GetTykExtension().Server.Authentication
	if a == nil {
		a = &Authentication{}
		s.GetTykExtension().Server.Authentication = a
	}

	if a.SecuritySchemes == nil {
		s.GetTykExtension().Server.Authentication.SecuritySchemes = make(map[string]interface{})
	}

	a.Enabled = !api.UseKeylessAccess
	a.StripAuthorizationData = api.StripAuthData
	a.BaseIdentityProvider = api.BaseIdentityProvidedBy

	s.fillToken(api)
	s.fillOAuth(api)

	if ShouldOmit(a) {
		s.GetTykExtension().Server.Authentication = nil
	}
}

func (s *OAS) fillApiKeyScheme(ac *apidef.AuthConfig) {
	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[ac.Name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[ac.Name] = ref
	}

	var loc, key string

	switch {
	case ref.Value.In == header || (ref.Value.In == "" && ac.AuthHeaderName != ""):
		loc = header
		key = ac.AuthHeaderName
		ac.AuthHeaderName = ""
	case ref.Value.In == query || (ref.Value.In == "" && ac.ParamName != ""):
		loc = query
		key = ac.ParamName
		ac.ParamName = ""
	case ref.Value.In == cookie || (ref.Value.In == "" && ac.CookieName != ""):
		loc = cookie
		key = ac.CookieName
		ac.CookieName = ""
	}

	ref.Value.WithName(key).WithIn(loc).WithType(apiKey)

	s.appendSecurity(ac.Name)
}

func (s *OAS) extractApiKeySchemeTo(ac *apidef.AuthConfig, name string) {
	ref := s.Components.SecuritySchemes[name]
	ac.Name = name

	switch ref.Value.In {
	case header:
		ac.AuthHeaderName = ref.Value.Name
	case query:
		ac.ParamName = ref.Value.Name
	case cookie:
		ac.CookieName = ref.Value.Name
	}
}

func (s *OAS) fillOauthScheme(accessTypes []osin.AccessRequestType, name string) {
	ss := s.Components.SecuritySchemes
	if ss == nil {
		ss = make(map[string]*openapi3.SecuritySchemeRef)
		s.Components.SecuritySchemes = ss
	}

	ref, ok := ss[name]
	if !ok {
		ref = &openapi3.SecuritySchemeRef{
			Value: openapi3.NewSecurityScheme(),
		}
		ss[name] = ref
	}

	flows := ref.Value.Flows
	if flows == nil {
		flows = &openapi3.OAuthFlows{}
	}

	for _, accessType := range accessTypes {
		switch accessType {
		case osin.AUTHORIZATION_CODE:
			if flows.AuthorizationCode == nil {
				flows.AuthorizationCode = &openapi3.OAuthFlow{}
			}

			setAuthorizationURLIfEmpty(flows.AuthorizationCode)
			setTokenURLIfEmpty(flows.AuthorizationCode)
			setScopesIfEmpty(flows.AuthorizationCode)
		case osin.CLIENT_CREDENTIALS:
			if flows.ClientCredentials == nil {
				flows.ClientCredentials = &openapi3.OAuthFlow{}
			}

			setTokenURLIfEmpty(flows.ClientCredentials)
			setScopesIfEmpty(flows.ClientCredentials)
		case osin.PASSWORD:
			if flows.Password == nil {
				flows.Password = &openapi3.OAuthFlow{}
			}

			setTokenURLIfEmpty(flows.Password)
			setScopesIfEmpty(flows.Password)
		case osin.IMPLICIT:
			if flows.Implicit == nil {
				flows.Implicit = &openapi3.OAuthFlow{}
			}

			setAuthorizationURLIfEmpty(flows.Implicit)
			setScopesIfEmpty(flows.Implicit)
		}
	}

	ref.Value.WithType(oauth2).Flows = flows

	s.appendSecurity(name)
}

func setAuthorizationURLIfEmpty(flow *openapi3.OAuthFlow) {
	if flow.AuthorizationURL == "" {
		flow.AuthorizationURL = "/oauth/authorize"
	}
}

func setTokenURLIfEmpty(flow *openapi3.OAuthFlow) {
	if flow.TokenURL == "" {
		flow.TokenURL = "/oauth/token"
	}
}

func setScopesIfEmpty(flow *openapi3.OAuthFlow) {
	if flow.Scopes == nil {
		flow.Scopes = make(map[string]string)
	}
}

func (s *OAS) appendSecurity(name string) {
	found := false
	for _, security := range s.Security {
		if _, ok := security[name]; ok {
			found = true
			break
		}
	}

	if !found {
		sec := openapi3.NewSecurityRequirement()
		sec[name] = []string{}
		s.Security.With(sec)
	}
}

func (s *OAS) extractOAuthSchemeTo(api *apidef.APIDefinition, name string) {
	ref := s.Components.SecuritySchemes[name]

	flows := ref.Value.Flows
	if flows == nil {
		return
	}

	if flows.AuthorizationCode != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.AUTHORIZATION_CODE)
	}

	if flows.ClientCredentials != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.CLIENT_CREDENTIALS)
	}

	if flows.Password != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.PASSWORD)
	}

	if flows.Implicit != nil {
		api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.IMPLICIT)
	}
}
