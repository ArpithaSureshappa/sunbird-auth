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
 *
 * <p>Also builds Deep Linking requests: Moodle's deep-linking endpoint
 * ({@value LtiConstants#DEEP_LINKING_URI_MARKER}) is a distinct URL from its resource-link
 * launch endpoint, arriving via the same redirect_uri client-session note - that URL is the
 * only signal distinguishing the two, since there's no separate flag for it. When matched,
 * emits {@code LtiDeepLinkingRequest} with a {@code deep_linking_settings} claim instead of
 * {@code resource_link}/{@code custom} (not applicable to Deep Linking) - {@code
 * target_link_uri} is still included either way, since it's a common required claim for
 * every LTI message type, not specific to resource-link launches.
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
        return "Injects LTI 1.3 claims only when the incoming authorize request carried "
                + "lti_message_hint; a no-op for every other login. Emits a resource-link launch "
                + "(message_type, target_link_uri, resource_link, roles) or, when redirect_uri "
                + "targets Moodle's deep-linking endpoint, a deep_linking_settings claim instead. "
                + "Reads everything directly from the client session - no authenticator or flow "
                + "change required.";
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

        boolean isDeepLinking = redirectUri != null && redirectUri.contains(LtiConstants.DEEP_LINKING_URI_MARKER);

        token.getOtherClaims().put(LtiConstants.CLAIM_VERSION, LtiConstants.LTI_VERSION);
        token.getOtherClaims().put(LtiConstants.CLAIM_DEPLOYMENT_ID, LtiConstants.PLACEHOLDER_DEPLOYMENT_ID);

        // target_link_uri is a common required claim for every LTI message type, not just
        // resource-link launches - it's simply "the URL this message was sent to."
        logger.infov("LtiProtocolMapper: redirect_uri client-session note = {0}", redirectUri);
        token.getOtherClaims().put(LtiConstants.CLAIM_TARGET_LINK_URI, redirectUri);

        String role = isDeepLinking ? LtiConstants.INSTRUCTOR_ROLE : LtiConstants.LEARNER_ROLE;
        token.getOtherClaims().put(LtiConstants.CLAIM_ROLES, Collections.singletonList(role));

        if (isDeepLinking) {
            logger.info("LtiProtocolMapper: redirect_uri matches Deep Linking endpoint; building LtiDeepLinkingRequest as Instructor");

            token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_DEEP_LINKING_REQUEST);

            Map<String, Object> deepLinkingSettings = new LinkedHashMap<>();
            deepLinkingSettings.put("deep_link_return_url", LtiConstants.PLACEHOLDER_DEEP_LINK_RETURN_URL);
            deepLinkingSettings.put("accept_types", Collections.singletonList("ltiResourceLink"));
            deepLinkingSettings.put("accept_presentation_document_targets", List.of("iframe", "window"));
            deepLinkingSettings.put("accept_multiple", false);
            deepLinkingSettings.put("data", ltiMessageHint);
            token.getOtherClaims().put(LtiConstants.CLAIM_DEEP_LINKING_SETTINGS, deepLinkingSettings);
        } else {
            token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_RESOURCE_LINK_REQUEST);

            Map<String, Object> resourceLink = new LinkedHashMap<>();
            resourceLink.put("id", LtiConstants.PLACEHOLDER_RESOURCE_LINK_ID);
            resourceLink.put("title", LtiConstants.PLACEHOLDER_RESOURCE_LINK_TITLE);
            token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

            Map<String, Object> custom = new LinkedHashMap<>();
            custom.put("id", LtiConstants.PLACEHOLDER_CUSTOM_ID);
            token.getOtherClaims().put(LtiConstants.CLAIM_CUSTOM, custom);
        }

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
