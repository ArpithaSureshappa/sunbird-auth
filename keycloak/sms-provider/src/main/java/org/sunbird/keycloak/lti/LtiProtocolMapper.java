package org.sunbird.keycloak.lti;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

/**
 * Injects the LTI 1.3 Core Message claims into the token, but only when the incoming authorize
 * request carried {@code lti_message_hint}. Deliberately reads it directly from the
 * {@link ClientSessionContext}'s {@code AuthenticatedClientSessionModel} - Keycloak copies the
 * authentication session's client notes (including non-standard request params, stored under
 * the {@code client_request_param_} prefix) into the client session automatically once login
 * completes. That means this mapper alone decides whether to inject LTI claims: no custom
 * Authenticator, no change to the realm's existing authentication flow, nothing that can
 * conflict with its Required/Alternative structure. An earlier version of this feature used a
 * companion Authenticator ({@link LtiMarkerAuthenticator}, still present but no longer wired
 * into any flow) to stash this value as a session note instead - abandoned after adding it as a
 * flow step broke the realm's Cookie/IdP-Redirector alternatives (Keycloak discards ALTERNATIVE
 * executions at a level that also has a REQUIRED one).
 *
 * <p>For every ordinary iGOT login that request param is absent, so {@link #setClaim} does
 * nothing - the existing {@code CustomProtocolMapper}'s claims (org, user_roles, etc.) are
 * untouched either way.
 *
 * <p>deployment_id / resource_link are PoC placeholders (see {@link LtiConstants}) until the
 * provider/content registry that used to live in cios-content-service is rebuilt elsewhere.
 */
public class LtiProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger logger = Logger.getLogger(LtiProtocolMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    public static final String PROVIDER_ID = "lti-claims-mapper";

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "LTI 1.3 Claims Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getHelpText() {
        return "Injects LTI 1.3 Core Message claims (message_type, deployment_id, target_link_uri, "
                + "resource_link, roles) only when the incoming authorize request carried "
                + "lti_message_hint; a no-op for every other login. Reads it directly from the "
                + "client session - no authenticator or flow change required.";
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                             KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        String ltiMessageHint = null;
        String redirectUri = null;
        if (clientSessionCtx != null && clientSessionCtx.getClientSession() != null) {
            ltiMessageHint = clientSessionCtx.getClientSession().getNote(LtiConstants.LTI_MESSAGE_HINT_CLIENT_NOTE);
            redirectUri = clientSessionCtx.getClientSession().getNote("redirect_uri");
        }
        logger.infov("LtiProtocolMapper: lti_message_hint client-session note = {0}", ltiMessageHint);

        if (ltiMessageHint == null || ltiMessageHint.isEmpty()) {
            logger.info("LtiProtocolMapper: lti_message_hint absent; not injecting LTI claims for this token");
            return;
        }

        logger.infov("LtiProtocolMapper: injecting LTI claims for lti_message_hint={0}", ltiMessageHint);

        token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_RESOURCE_LINK_REQUEST);
        token.getOtherClaims().put(LtiConstants.CLAIM_VERSION, LtiConstants.LTI_VERSION);
        token.getOtherClaims().put(LtiConstants.CLAIM_DEPLOYMENT_ID, LtiConstants.PLACEHOLDER_DEPLOYMENT_ID);

        logger.infov("LtiProtocolMapper: redirect_uri client-session note = {0}", redirectUri);
        token.getOtherClaims().put(LtiConstants.CLAIM_TARGET_LINK_URI, redirectUri);

        Map<String, Object> resourceLink = new LinkedHashMap<>();
        resourceLink.put("id", LtiConstants.PLACEHOLDER_RESOURCE_LINK_ID);
        resourceLink.put("title", LtiConstants.PLACEHOLDER_RESOURCE_LINK_TITLE);
        token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

        token.getOtherClaims().put(LtiConstants.CLAIM_ROLES, Collections.singletonList(LtiConstants.LEARNER_ROLE));

//        Map<String, Object> custom = new LinkedHashMap<>();
//        custom.put("id", LtiConstants.PLACEHOLDER_CUSTOM_ID);
//        token.getOtherClaims().put(LtiConstants.CLAIM_CUSTOM, custom);

        logger.info("LtiProtocolMapper: LTI claims injected successfully");
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        if (accessToken) {
            config.put("access.token.claim", "true");
        }
        if (idToken) {
            config.put("id.token.claim", "true");
        }
        if (userInfo) {
            config.put("userinfo.token.claim", "true");
        }
        mapper.setConfig(config);
        return mapper;
    }

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, LtiProtocolMapper.class);
    }
}
