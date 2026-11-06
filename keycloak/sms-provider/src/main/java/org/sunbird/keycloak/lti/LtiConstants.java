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

    /** Substring markers used to detect a Deep Linking launch: every Tool's deep-linking
     *  endpoint is a distinct URL from its resource-link launch endpoint, arriving via the
     *  same redirect_uri client-session note - no separate flag exists to tell them apart, so
     *  the URL itself is the signal. Each Tool names its endpoint differently (Moodle:
     *  "launch_deeplink.php", Coursera: ".../deep-linking/launch"), so this is a per-Tool list,
     *  not a single pattern - extend it here when a new Tool is onboarded, until a real
     *  per-Tool registry replaces this entirely. */
    public static final List<String> DEEP_LINKING_URI_MARKERS = List.of(
            "launch_deeplink.php",
            "deep-linking/launch"
    );

    /** Full set of LTI Deep Linking content-item types (spec section on Content Item Types).
     *  Not narrowed to just "ltiResourceLink" - a Tool's content picker shouldn't be
     *  artificially restricted to one item type when the Platform can accept any of these. */
    public static final List<String> ACCEPTED_DEEP_LINKING_TYPES = List.of(
            "link", "file", "html", "ltiResourceLink", "image"
    );

    /** Real receiving endpoint: LtiController#handleDeepLinkingReturn in cios-content-service,
     *  under that service's actual base path (/ciosIntegration/lti/...), fronted by a public,
     *  unauthenticated Kong route direct to cios-content-service - no iGOT session exists for
     *  external Tools posting here, so it can't go through uiproxy's protected /proxies/v8 tier. */
    public static final String DEEP_LINK_RETURN_URL =
            "https://portal.dev.karmayogibharat.net/api/ciosIntegration/lti/deeplink/return";

    /** PoC placeholders: no provider/resource-link registry exists since the removal of
     *  cios-content-service's LTI package. Single hardcoded deployment, matching the one
     *  Deployment ID ("1") registered on Moodle's side today. Replace with a real per-Tool,
     *  per-content lookup once that registry is rebuilt. */
    public static final String PLACEHOLDER_DEPLOYMENT_ID = "1";
    public static final String PLACEHOLDER_RESOURCE_LINK_ID = "1";
    public static final String PLACEHOLDER_RESOURCE_LINK_TITLE = "iGOT LTI Resource";

    /** Moodle's enrol_lti "Publish as LTI tool" Custom properties value for the one PoC
     *  resource ("Course: test course") - Moodle's launch.php rejects the launch without a
     *  matching custom.id claim, separate from resource_link.id. */
    public static final String PLACEHOLDER_CUSTOM_ID = "602ba6d8-da5e-4ffa-8ed3-ffeab3211ebe";


    public static final String LEARNER_ROLE =
            "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";

    /** Deep Linking / content-selection in Moodle's enrol_lti is a teacher-facing workflow -
     *  confirmed directly against the "test course" published resource's settings, which gate
     *  provisioning separately per role ("Teacher first launch provisioning mode" vs "Student
     *  first launch provisioning mode"). Sending Learner for a Deep Linking launch routes
     *  through the student path instead, which is why the content picker came back empty. */
    public static final String INSTRUCTOR_ROLE =
            "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor";
}
