package org.sunbird.keycloak.lti;

import java.util.List;

/** Shared keys/URIs for the LTI 1.3 marker authenticator + protocol mapper pair. */
public final class LtiConstants {

    private LtiConstants() {
    }

    /** Our own key for the user-session note we set ourselves once an LTI launch is detected -
     *  not a Keycloak-populated value, so no prefix needed here. */
    public static final String LTI_MESSAGE_HINT_PARAM = "lti_message_hint";

    /** The client note key Keycloak actually stores lti_message_hint under. Keycloak prefixes
     *  any OIDC request parameter it doesn't natively recognize with "client_request_param_"
     *  (standard ones like nonce/redirect_uri/scope are NOT prefixed) - confirmed directly from
     *  a live AuthenticationFlowContext dump: {@code client_request_param_lti_message_hint=...}. */
    public static final String LTI_MESSAGE_HINT_CLIENT_NOTE = "client_request_param_lti_message_hint";

    /** Same Keycloak client-note prefixing behavior as {@link #LTI_MESSAGE_HINT_CLIENT_NOTE},
     *  for the {@code lti_deployment_id} request param - its value is the partner's own
     *  partnerCode (e.g. "IGOT-MOODLE-W8HF4"), echoed back verbatim as the deployment_id claim
     *  rather than a hardcoded placeholder. */
    public static final String LTI_DEPLOYMENT_ID_CLIENT_NOTE = "client_request_param_lti_deployment_id";

    public static final String CLAIM_MESSAGE_TYPE = "https://purl.imsglobal.org/spec/lti/claim/message_type";
    public static final String CLAIM_VERSION = "https://purl.imsglobal.org/spec/lti/claim/version";
    public static final String CLAIM_DEPLOYMENT_ID = "https://purl.imsglobal.org/spec/lti/claim/deployment_id";
    public static final String CLAIM_TARGET_LINK_URI = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri";
    public static final String CLAIM_RESOURCE_LINK = "https://purl.imsglobal.org/spec/lti/claim/resource_link";
    public static final String CLAIM_ROLES = "https://purl.imsglobal.org/spec/lti/claim/roles";
    public static final String CLAIM_CUSTOM = "https://purl.imsglobal.org/spec/lti/claim/custom";
    public static final String CLAIM_DEEP_LINKING_SETTINGS = "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings";

    public static final String MESSAGE_TYPE_RESOURCE_LINK_REQUEST = "LtiResourceLinkRequest";
    public static final String MESSAGE_TYPE_DEEP_LINKING_REQUEST = "LtiDeepLinkingRequest";
    public static final String LTI_VERSION = "1.3.0";
    public static final List<String> ACCEPTED_DEEP_LINKING_TYPES = List.of(
            "link", "file", "html", "ltiResourceLink", "image"
    );
    public static final String DEEP_LINK_RETURN_URL =
            "https://portal.dev.karmayogibharat.net/api/ciosIntegration/lti/deeplink/return";
    public static final String PLACEHOLDER_RESOURCE_LINK_TITLE = "iGOT LTI Resource";
    public static final String CLAIM_AGS_ENDPOINT = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint";
    public static final List<String> AGS_SCOPES = List.of(
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/score"
    );
    /** Env var holding cios-content-service's own direct base URL (not the Kong-routed public
     *  one) - AGS calls go straight to the service, not through the gateway. */
    public static final String CIOS_SERVICE_BASE_URL_ENV = "CIOS_CONTENT_SERVICE_API_BASE";
    public static final String AGS_LINEITEM_PATH = "/ciosIntegration/lti/ags/lineitems/lineitem";

    public static final int MAX_SUBJECT_LENGTH_FOR_LTI = 62;

    public static final String LEARNER_ROLE =
            "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
    public static final String INSTRUCTOR_ROLE =
            "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor";
}
