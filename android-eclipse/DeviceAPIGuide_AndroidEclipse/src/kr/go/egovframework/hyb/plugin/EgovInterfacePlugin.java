package kr.go.egovframework.hyb.plugin;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;

public class EgovInterfacePlugin extends CordovaPlugin {

    public static final String GET_SERVER_URL = "URL";
    public static final String ERROR_MESSAGE_JSON = "Json Parsing Error";
    public static final String ERROR_MESSAGE_IO = "IO Error";
    public static final String ERROR_MESSAGE_ACTION = "Action Input Error";

    private static final CookieManager COOKIE_MANAGER =
            new CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER);

    static {
        CookieHandler.setDefault(COOKIE_MANAGER);
    }

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) {
        Context context = cordova.getActivity();

        Log.d(getClass().getSimpleName(), " >>>>> INIT");

        String serverUrl = getServerUrl(context);

        if (GET_SERVER_URL.equals(action)) {
            new InterfaceCommTask().execute(action, serverUrl, data, callbackContext);
            return true;
        }

        if (!EgovInterfaceRequestValidator.HTTP_METHOD_GET.equals(action)
                && !EgovInterfaceRequestValidator.HTTP_METHOD_POST.equals(action)) {
            callbackContext.error(ERROR_MESSAGE_ACTION);
            return true;
        }
        if (!EgovInterfaceRequestValidator.isSecureServerUrl(context, serverUrl)) {
            callbackContext.error(EgovInterfaceRequestValidator.ERROR_SECURE_URL);
            return true;
        }

        new InterfaceCommTask().execute(action, serverUrl, data, callbackContext);
        return true;
    }

    private static String getServerUrl(Context context) {
        int resourceId = context.getResources().getIdentifier(
                "SERVER_URL", "string", context.getPackageName());
        if (resourceId == 0) {
            return "";
        }
        return context.getString(resourceId);
    }

    private static String parseParameter(JSONObject requestMap) throws Exception {
        StringBuffer sb = new StringBuffer();
        Iterator<?> iterator = requestMap.keys();
        int paramSize = requestMap.length();
        int count = 1;
        while (iterator.hasNext()) {
            String key = (String) iterator.next();
            sb.append(key);
            sb.append("=");
            sb.append(URLEncoder.encode(requestMap.get(key).toString(), "utf-8"));
            if (paramSize > count) {
                sb.append("&");
            }
            count++;
        }
        return sb.toString();
    }

    private static HttpHeaders buildRequestHeaders(String acceptType) {
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if ("json".equals(acceptType)) {
            requestHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        } else {
            requestHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_XML));
            List<Charset> charset = new ArrayList<Charset>(Charset.availableCharsets().values());
            charset.add(Charset.forName("UTF-8"));
            requestHeaders.setAcceptCharset(charset);
        }
        return requestHeaders;
    }

    public class InterfaceCommTask extends AsyncTask<Object, Integer, String> {

        String action;
        String serverUrl;
        JSONArray data;
        CallbackContext callbackContext;

        @Override
        protected String doInBackground(Object... params) {
            action = (String) params[0];
            serverUrl = (String) params[1];
            data = (JSONArray) params[2];
            callbackContext = (CallbackContext) params[3];

            if (GET_SERVER_URL.equals(action)) {
                try {
                    callbackContext.success(serverUrl);
                } catch (Exception e) {
                    callbackContext.error(ERROR_MESSAGE_IO);
                }
                return null;
            }

            try {
                String uri = EgovInterfaceRequestValidator.normalizeUri(data.getString(0));
                String acceptType = EgovInterfaceRequestValidator.normalizeAcceptType(data.getString(1));
                JSONObject param = EgovInterfaceRequestValidator.sanitizeParameters(
                        action, data.optJSONObject(2));

                RestTemplate restTemplate = new RestTemplate();
                restTemplate.getMessageConverters().add(new StringHttpMessageConverter());
                ResponseEntity<String> responseEntity;

                if (EgovInterfaceRequestValidator.HTTP_METHOD_GET.equals(action)) {
                    HttpEntity<String> requestEntity =
                            new HttpEntity<String>("", buildRequestHeaders(acceptType));
                    responseEntity = restTemplate.exchange(
                            serverUrl + uri + "?" + parseParameter(param),
                            HttpMethod.GET, requestEntity, String.class);
                } else {
                    HttpEntity<String> requestEntity = new HttpEntity<String>(
                            parseParameter(param), buildRequestHeaders(acceptType));
                    responseEntity = restTemplate.exchange(
                            serverUrl + uri, HttpMethod.POST, requestEntity, String.class);
                }

                callbackContext.success(
                        EgovInterfaceRequestValidator.sanitizeResponseBody(responseEntity.getBody()));
            } catch (JSONException e) {
                callbackContext.error(e.getMessage());
            } catch (RestClientException e) {
                callbackContext.error(e.getLocalizedMessage());
            } catch (Exception e) {
                callbackContext.error(ERROR_MESSAGE_IO);
            }

            return null;
        }
    }
}
