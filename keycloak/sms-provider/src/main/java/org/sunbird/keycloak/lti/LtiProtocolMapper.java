package org.sunbird.keycloak.lti;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
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
 * <p>Also builds Deep Linking requests: each Tool's deep-linking endpoint (see {@link
 * LtiConstants#DEEP_LINKING_URI_MARKERS}) is a distinct URL from its resource-link launch
 * endpoint, arriving via the same redirect_uri client-session note - that URL is the only
 * signal distinguishing the two, since there's no separate flag for it. When matched,
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

        boolean isDeepLinking = redirectUri != null
                && LtiConstants.DEEP_LINKING_URI_MARKERS.stream().anyMatch(redirectUri::contains);

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
            deepLinkingSettings.put("deep_link_return_url", LtiConstants.DEEP_LINK_RETURN_URL);//igot return url
            deepLinkingSettings.put("accept_types", LtiConstants.ACCEPTED_DEEP_LINKING_TYPES);//"link", "file", "html",
            deepLinkingSettings.put("accept_presentation_document_targets", List.of("iframe", "window"));
            deepLinkingSettings.put("accept_multiple", false);
            deepLinkingSettings.put("data", ltiMessageHint);
            token.getOtherClaims().put(LtiConstants.CLAIM_DEEP_LINKING_SETTINGS, deepLinkingSettings);
        } else {
            token.getOtherClaims().put(LtiConstants.CLAIM_MESSAGE_TYPE, LtiConstants.MESSAGE_TYPE_RESOURCE_LINK_REQUEST);

            // AGS endpoint claim - required by Adobe/Coursera to accept a resource-link launch
            // even without real grade sync; see LtiConstants.CLAIM_AGS_ENDPOINT javadoc.
            Map<String, Object> agsEndpoint = new LinkedHashMap<>();
            agsEndpoint.put("scope", LtiConstants.AGS_SCOPES);
            agsEndpoint.put("lineitems", LtiConstants.PLACEHOLDER_LINEITEMS_URL);
            agsEndpoint.put("lineitem", LtiConstants.PLACEHOLDER_LINEITEM_URL);
            token.getOtherClaims().put(LtiConstants.CLAIM_AGS_ENDPOINT, agsEndpoint);

            boolean isAdobe = redirectUri != null && redirectUri.contains(LtiConstants.ADOBE_LAUNCH_URI_MARKER);
            boolean isCourseLaunch = ltiMessageHint.startsWith(LtiConstants.LTI_MESSAGE_HINT_COURSE_LAUNCH_PREFIX);

            if (isAdobe) {
                // Adobe's own backend only supports a sub up to MAX_SUBJECT_LENGTH_FOR_LTI chars
                // (confirmed by Adobe engineering - see that constant's javadoc) and otherwise
                // crashes with a generic 500 during launch processing. Scoped to Adobe only -
                // other Tools haven't reported this limit, so their sub is left untouched.
                String originalSubject = token.getSubject();
                String shortenedSubject = shortenSubjectForLti(originalSubject);
                if (!shortenedSubject.equals(originalSubject)) {
                    logger.infov("LtiProtocolMapper: sub exceeds {0} chars ({1}); shortening for Adobe: {2} -> {3}",
                            LtiConstants.MAX_SUBJECT_LENGTH_FOR_LTI, originalSubject.length(), originalSubject, shortenedSubject);
                    token.setSubject(shortenedSubject);
                }

                // Adobe's own /login_initiations handler strips the query string off
                // target_link_uri before echoing it back as redirect_uri (confirmed from a real
                // captured launch: target_link_uri claim came back as plain ".../launch", no
                // ?exportUuid=... at all) - so exportUuid can't be read from redirect_uri here.
                // lti_message_hint is the one value proven to survive the round trip, so the test
                // harness puts the raw exportUuid there instead. Adobe's own error page names the
                // field it wants verbatim ("valid ExportUuid parameter"), so custom uses that
                // exact key rather than the generic "id" used for Moodle's placeholder shape.
                // ltiMessageHint is already confirmed non-null/non-empty by the guard clause above.
                String exportUuid = ltiMessageHint;
                String resourceId = exportUuid != null ? exportUuid : LtiConstants.PLACEHOLDER_RESOURCE_LINK_ID;

                logger.infov("LtiProtocolMapper: redirect_uri matches Adobe Learning Manager; using exportUuid={0} from lti_message_hint", exportUuid);

                Map<String, Object> resourceLink = new LinkedHashMap<>();
                resourceLink.put("id", resourceId);
                token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

                Map<String, Object> custom = new LinkedHashMap<>();
                custom.put(LtiConstants.ADOBE_EXPORT_UUID_PARAM, resourceId);
                token.getOtherClaims().put(LtiConstants.CLAIM_CUSTOM, custom);
            } else if (isCourseLaunch) {
                // Real course launch: lti_message_hint carries "courseLaunch:{contentId}" -
                // contentId is cb-pores-service's own content identifier (the URL the frontend
                // builds includes it verbatim, e.g. "courseLaunch:ext_114467417409765376132").
                // Rather than hardcoding any one provider's custom-claim shape here, read the
                // course's own providerCustomClaim - it already holds Moodle's {"id": ...} shape
                // or Coursera's {link_type, course_id, organization_id, program_id, ...} shape,
                // captured verbatim from that provider at content-onboarding time. No per-Tool
                // branching needed - whatever shape the course's own record has is what's sent.
                String contentId = ltiMessageHint.substring(LtiConstants.LTI_MESSAGE_HINT_COURSE_LAUNCH_PREFIX.length());
                logger.infov("LtiProtocolMapper: courseLaunch message hint; fetching providerCustomClaim for contentId={0}", contentId);

                JsonNode providerCustomClaim = fetchProviderCustomClaim(contentId);

                Map<String, Object> resourceLink = new LinkedHashMap<>();
                resourceLink.put("id", contentId);
                token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

                Map<String, Object> custom;
                if (!providerCustomClaim.isMissingNode() && !providerCustomClaim.isNull() && providerCustomClaim.isObject()) {
                    custom = new ObjectMapper().convertValue(providerCustomClaim, LinkedHashMap.class);
                } else {
                    // Course lookup failed or has no providerCustomClaim recorded - degrade to
                    // Moodle's safe generic shape rather than blocking login entirely.
                    logger.warnv("LtiProtocolMapper: no providerCustomClaim found for contentId={0}; falling back to {{id: contentId}}", contentId);
                    custom = new LinkedHashMap<>();
                    custom.put("id", contentId);
                }
                token.getOtherClaims().put(LtiConstants.CLAIM_CUSTOM, custom);
            } else {
                Map<String, Object> resourceLink = new LinkedHashMap<>();
                resourceLink.put("id", LtiConstants.PLACEHOLDER_RESOURCE_LINK_ID);
               // resourceLink.put("title", LtiConstants.PLACEHOLDER_RESOURCE_LINK_TITLE);
                token.getOtherClaims().put(LtiConstants.CLAIM_RESOURCE_LINK, resourceLink);

                Map<String, Object> custom = new LinkedHashMap<>();
                custom.put("id", LtiConstants.PLACEHOLDER_CUSTOM_ID);
                token.getOtherClaims().put(LtiConstants.CLAIM_CUSTOM, custom);
            }
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

    /**
     * Reads the given course's own {@code providerCustomClaim} from cb-pores-service's
     * content-read API, so Coursera/Moodle/future-provider launches send whatever custom-claim
     * shape was captured verbatim for that course at onboarding time, instead of one hardcoded
     * shape baked into this mapper. Returns {@link MissingNode} on any failure (unreachable
     * service, 404, malformed response, missing field) - a failed lookup must degrade the
     * launch's custom claim, never block token issuance entirely, same philosophy as every
     * other live-fetch in this class.
     */
    private static JsonNode fetchProviderCustomClaim(String contentId) {
        String baseUrl = System.getenv(LtiConstants.CB_PORES_SERVICE_BASE_URL_ENV);
        if (baseUrl == null || baseUrl.isEmpty()) {
            logger.warnv("LtiProtocolMapper: {0} env var not set; cannot fetch providerCustomClaim for contentId={1}", LtiConstants.CB_PORES_SERVICE_BASE_URL_ENV, contentId);
            return MissingNode.getInstance();
        }
        String url = baseUrl + LtiConstants.CONTENT_READ_PATH + contentId;
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int status = connection.getResponseCode();
            if (status != 200) {
                logger.warnv("LtiProtocolMapper: content-read API returned HTTP {0} for contentId={1}", status, contentId);
                return MissingNode.getInstance();
            }

            StringBuilder body = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    body.append(line);
                }
            }

            JsonNode root = new ObjectMapper().readTree(body.toString());
            return root.path(LtiConstants.CONTENT_FIELD).path(LtiConstants.PROVIDER_CUSTOM_CLAIM_FIELD);
        } catch (Exception e) {
            logger.warnv(e, "LtiProtocolMapper: failed to fetch providerCustomClaim for contentId={0} from {1}", contentId, url);
            return MissingNode.getInstance();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
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
