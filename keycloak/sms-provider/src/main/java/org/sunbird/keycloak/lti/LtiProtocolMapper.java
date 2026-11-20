package org.sunbird.keycloak.lti;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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
        String ltiDeploymentId = null;
        if (clientSessionCtx != null && clientSessionCtx.getClientSession() != null) {
            ltiMessageHint = clientSessionCtx.getClientSession().getNote(LtiConstants.LTI_MESSAGE_HINT_CLIENT_NOTE);
            redirectUri = clientSessionCtx.getClientSession().getNote("redirect_uri");
            ltiDeploymentId = clientSessionCtx.getClientSession().getNote(LtiConstants.LTI_DEPLOYMENT_ID_CLIENT_NOTE);
        }
        logger.infov("LtiProtocolMapper: lti_message_hint client-session note = {0}", ltiMessageHint);

        if (ltiMessageHint == null || ltiMessageHint.isEmpty()) {
            logger.info("LtiProtocolMapper: lti_message_hint absent; not injecting LTI claims for this token");
            return;
        }

        logger.infov("LtiProtocolMapper: injecting LTI claims for lti_message_hint={0}", ltiMessageHint);

        String originalSubject = token.getSubject();
        String shortenedSubject = shortenSubjectForLti(originalSubject);
        if (!shortenedSubject.equals(originalSubject)) {
            logger.infov("LtiProtocolMapper: sub exceeds {0} chars ({1}); shortening for LTI: {2} -> {3}",
                    LtiConstants.MAX_SUBJECT_LENGTH_FOR_LTI, originalSubject.length(), originalSubject, shortenedSubject);
            token.setSubject(shortenedSubject);
        }

        // lti_deployment_id never survives the Tool's login-initiation -> Platform /auth
        // redirect (not a standard OIDC Authentication Request parameter, confirmed absent from
        // real captured tokens for Moodle/Coursera/Adobe alike) - lti_message_hint is the one
        // value proven to survive, so it carries partnerCode (== deployment_id) instead, in
        // different shapes per message type:
        //   Deep Linking:    "Deeplink:{partnerCode}"           (plain prefixed string)
        //   Resource link:   JSON with a "partnerCode" key, alongside whatever other
        //                    provider-specific fields the custom claim itself needs.
        boolean isDeepLinking = ltiMessageHint.startsWith("Deeplink:");

        Map<String, Object> decodedHint = null;
        String deploymentId;
        if (isDeepLinking) {
            deploymentId = ltiMessageHint.substring("Deeplink:".length());
        } else {
            decodedHint = tryDecodeJsonCustomClaim(ltiMessageHint);
            // Removed from the map (not just read) - partnerCode is this mapper's own
            // extraction key for the deployment_id claim, not something the Tool's custom-claim
            // processing needs to see alongside its own fields.
            Object partnerCodeFromHint = decodedHint != null ? decodedHint.remove("partnerCode") : null;
            deploymentId = partnerCodeFromHint != null ? String.valueOf(partnerCodeFromHint) : ltiDeploymentId;
        }

        token.getOtherClaims().put(LtiConstants.CLAIM_VERSION, LtiConstants.LTI_VERSION);
        token.getOtherClaims().put(LtiConstants.CLAIM_DEPLOYMENT_ID, deploymentId);

        // target_link_uri is a common required claim for every LTI message type, not just
        // resource-link launches - it's simply "the URL this message was sent to."
        logger.infov("LtiProtocolMapper: redirect_uri client-session note = {0}", redirectUri);
        token.getOtherClaims().put(LtiConstants.CLAIM_TARGET_LINK_URI, redirectUri);

        String role = isDeepLinking ? LtiConstants.INSTRUCTOR_ROLE : LtiConstants.LEARNER_ROLE;
        token.getOtherClaims().put(LtiConstants.CLAIM_ROLES, Collections.singletonList(role));

        if (isDeepLinking) {
            logger.infov("LtiProtocolMapper: lti_message_hint starts with Deeplink:; building LtiDeepLinkingRequest as Instructor, deploymentId={0}", deploymentId);

            token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_DEEP_LINKING_REQUEST);

            Map<String, Object> deepLinkingSettings = new LinkedHashMap<>();
            String returnUrl = LtiConstants.DEEP_LINK_RETURN_URL + "?partnerCode="
                    + URLEncoder.encode(deploymentId, StandardCharsets.UTF_8).replace("+", "%20");
            deepLinkingSettings.put("deep_link_return_url", returnUrl);//igot return url
            deepLinkingSettings.put("accept_types", LtiConstants.ACCEPTED_DEEP_LINKING_TYPES);//"link", "file", "html",
            deepLinkingSettings.put("accept_presentation_document_targets", List.of("iframe", "window"));
            deepLinkingSettings.put("accept_multiple", false);
            deepLinkingSettings.put("data", ltiMessageHint);
            token.getOtherClaims().put(LtiConstants.CLAIM_DEEP_LINKING_SETTINGS, deepLinkingSettings);
        } else {
            token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_RESOURCE_LINK_REQUEST);
            Map<String, Object> agsEndpoint = new LinkedHashMap<>();
            agsEndpoint.put("scope", LtiConstants.AGS_SCOPES);
            agsEndpoint.put("lineitems", LtiConstants.PLACEHOLDER_LINEITEMS_URL);
            agsEndpoint.put("lineitem", LtiConstants.PLACEHOLDER_LINEITEM_URL);
            token.getOtherClaims().put(LtiConstants.CLAIM_AGS_ENDPOINT, agsEndpoint);

            Map<String, Object> resourceLink = new LinkedHashMap<>();
            resourceLink.put("id", ltiMessageHint);
            token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

            Map<String, Object> custom = decodedHint != null ? decodedHint : Map.of("id", ltiMessageHint);
            token.getOtherClaims().put(LtiConstants.CLAIM_CUSTOM, custom);
        }

        logger.info("LtiProtocolMapper: LTI claims injected successfully");
    }

    /**
     * See {@link LtiConstants#MAX_SUBJECT_LENGTH_FOR_LTI} javadoc. Keycloak's federated-user
     * subject format is {@code f:<federation-link-uuid>:<raw-user-id>} - stripping down to the
     * part after the last colon recovers the raw user id (typically a 36-char UUID), which is
     * still stable/unique per user and comfortably under the limit. Falls back to the original
     * value unchanged if it's already short enough, or if it doesn't match the expected
     * federated shape (so a sub that's long for some other reason isn't mangled silently).
     */
    private static String shortenSubjectForLti(String originalSubject) {
        if (originalSubject == null || originalSubject.length() <= LtiConstants.MAX_SUBJECT_LENGTH_FOR_LTI) {
            return originalSubject;
        }
        int lastColon = originalSubject.lastIndexOf(':');
        if (lastColon >= 0 && lastColon < originalSubject.length() - 1) {
            String rawUserId = originalSubject.substring(lastColon + 1);
            if (rawUserId.length() <= LtiConstants.MAX_SUBJECT_LENGTH_FOR_LTI) {
                return rawUserId;
            }
        }
        return originalSubject;
    }

    private static Map<String, Object> tryDecodeJsonCustomClaim(String ltiMessageHint) {
        try {
            String decoded = URLDecoder.decode(ltiMessageHint, StandardCharsets.UTF_8);
            JsonNode node = new ObjectMapper().readTree(decoded);
            if (node.isObject()) {
                return new ObjectMapper().convertValue(node, LinkedHashMap.class);
            }
            logger.warnv("LtiProtocolMapper: decoded lti_message_hint is not a JSON object: {0}", decoded);
        } catch (Exception e) {
            logger.warnv(e, "LtiProtocolMapper: failed to decode lti_message_hint as JSON: {0}", ltiMessageHint);
        }
        return null;
    }

    /**
     * Plain query-string lookup, no new dependency needed - url is the redirect_uri client
     * session note (e.g. Adobe's own launch URL with ?exportUuid=...), not something requiring
     * full URI validation.
     */
    private static String extractQueryParam(String url, String paramName) {
        if (url == null) {
            return null;
        }
        int queryStart = url.indexOf('?');
        if (queryStart < 0) {
            return null;
        }
        for (String pair : url.substring(queryStart + 1).split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(paramName)) {
                return pair.substring(eq + 1);
            }
        }
        return null;
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
