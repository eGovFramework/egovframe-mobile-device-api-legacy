package kr.go.egovframework.hyb.plugin;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import android.content.Context;
import android.content.res.XmlResourceParser;

/**
 * Validates EgovInterfacePlugin requests before they reach the server.
 * HTTPS enforcement is controlled by a single {@code res/xml/network_policy.xml}
 * file ({@code require-https} attribute). Change the value before build:
 * {@code false} for local HTTP, {@code true} for release HTTPS.
 */
public final class EgovInterfaceRequestValidator {

    public static final String HTTP_METHOD_GET = "GET";
    public static final String HTTP_METHOD_POST = "POST";

    public static final String ERROR_SECURE_URL = "HTTPS server URL is required";
    public static final String ERROR_URI = "URI is not allowed";
    public static final String ERROR_PARAM = "Parameter input is invalid";
    public static final String ERROR_ACCEPT = "Accept type is invalid";

    private static final int MAX_URI_LENGTH = 256;
    private static final int MAX_PARAM_COUNT = 32;
    private static final int MAX_PARAM_KEY_LENGTH = 64;
    private static final int MAX_PARAM_VALUE_LENGTH = 8192;

    private static final Pattern URI_PATH_PATTERN =
            Pattern.compile("^/[a-zA-Z0-9][a-zA-Z0-9_./-]*$");
    private static final Pattern PARAM_KEY_PATTERN =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]*$");

    private static final Set<String> ALLOWED_API_PREFIXES = new HashSet<String>(Arrays.asList(
            "/acl/", "/cmr/", "/cps/", "/ctt/", "/dvc/", "/frw/", "/gps/", "/itf/",
            "/mda/", "/nwk/", "/vbr/", "/pus/", "/fop/", "/stm/", "/bar/", "/upd/", "/jai/"));

    private static final Set<String> GET_BLOCKED_PARAM_KEYS = new HashSet<String>(Arrays.asList(
            "userpw", "password", "passwd", "pwd", "secret", "token", "accesstoken", "refreshtoken"));

    private EgovInterfaceRequestValidator() {
    }

    public static boolean isSecureServerUrl(Context context, String serverUrl) {
        try {
            URI uri = URI.create(serverUrl.trim());
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return false;
            }
            if (!isRequireHttps(context)) {
                return true;
            }
            return "https".equalsIgnoreCase(scheme);
        } catch (Exception e) {
            return false;
        }
    }

    public static String normalizeUri(String rawUri) throws JSONException {
        if (rawUri == null || rawUri.trim().isEmpty()) {
            throw new JSONException(ERROR_URI);
        }

        String path = rawUri.trim();
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) {
            path = path.substring(0, queryIndex);
        }
        int fragmentIndex = path.indexOf('#');
        if (fragmentIndex >= 0) {
            path = path.substring(0, fragmentIndex);
        }

        if (path.length() > MAX_URI_LENGTH
                || path.contains("..")
                || path.contains("\\")
                || path.contains("%")
                || !path.startsWith("/")
                || !URI_PATH_PATTERN.matcher(path).matches()) {
            throw new JSONException(ERROR_URI);
        }

        if (!isAllowedUri(path)) {
            throw new JSONException(ERROR_URI);
        }

        return path;
    }

    public static String normalizeAcceptType(String acceptType) throws JSONException {
        if (acceptType == null) {
            throw new JSONException(ERROR_ACCEPT);
        }
        String normalized = acceptType.trim().toLowerCase(Locale.ENGLISH);
        if (!"json".equals(normalized) && !"xml".equals(normalized)) {
            throw new JSONException(ERROR_ACCEPT);
        }
        return normalized;
    }

    public static JSONObject sanitizeParameters(String httpMethod, JSONObject requestMap) throws JSONException {
        if (requestMap == null) {
            return new JSONObject();
        }

        if (requestMap.length() > MAX_PARAM_COUNT) {
            throw new JSONException(ERROR_PARAM);
        }

        JSONObject sanitized = new JSONObject();
        Iterator<?> iterator = requestMap.keys();
        while (iterator.hasNext()) {
            String key = (String) iterator.next();
            validateParameterKey(httpMethod, key);
            Object value = requestMap.get(key);
            sanitized.put(key, normalizeParameterValue(value));
        }
        return sanitized;
    }

    public static String sanitizeResponseBody(String body) {
        if (body == null || body.isEmpty()) {
            return body;
        }
        return body
                .replaceAll("(?i)(<userPw>)([^<]*)(</userPw>)", "$1****$3")
                .replaceAll("(?i)(<USER_PW>)([^<]*)(</USER_PW>)", "$1****$3")
                .replaceAll("(?i)(\"userPw\"\\s*:\\s*\")([^\"]*)(\")", "$1****$3")
                .replaceAll("(?i)(\"USER_PW\"\\s*:\\s*\")([^\"]*)(\")", "$1****$3");
    }

    public static boolean isRequireHttps(Context context) {
        int resourceId = context.getResources().getIdentifier(
                "network_policy", "xml", context.getPackageName());
        if (resourceId == 0) {
            return false;
        }

        XmlResourceParser parser = context.getResources().getXml(resourceId);
        try {
            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG
                        && "network-policy".equals(parser.getName())) {
                    String value = parser.getAttributeValue(null, "require-https");
                    if (value == null || value.trim().isEmpty()) {
                        return false;
                    }
                    return Boolean.parseBoolean(value.trim());
                }
                eventType = parser.next();
            }
        } catch (XmlPullParserException e) {
            return false;
        } catch (IOException e) {
            return false;
        } finally {
            parser.close();
        }
        return false;
    }

    private static boolean isAllowedUri(String uri) {
        for (String prefix : ALLOWED_API_PREFIXES) {
            if (uri.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static void validateParameterKey(String httpMethod, String key) throws JSONException {
        if (key == null
                || key.length() > MAX_PARAM_KEY_LENGTH
                || !PARAM_KEY_PATTERN.matcher(key).matches()) {
            throw new JSONException(ERROR_PARAM);
        }
        if (HTTP_METHOD_GET.equals(httpMethod)
                && GET_BLOCKED_PARAM_KEYS.contains(key.toLowerCase(Locale.ENGLISH))) {
            throw new JSONException("Sensitive parameter is not allowed in GET");
        }
    }

    private static String normalizeParameterValue(Object value) throws JSONException {
        if (value == null || JSONObject.NULL.equals(value)) {
            return "";
        }
        String text = String.valueOf(value);
        if (text.length() > MAX_PARAM_VALUE_LENGTH) {
            throw new JSONException(ERROR_PARAM);
        }
        if (text.indexOf('\0') >= 0) {
            throw new JSONException(ERROR_PARAM);
        }
        return text;
    }
}
