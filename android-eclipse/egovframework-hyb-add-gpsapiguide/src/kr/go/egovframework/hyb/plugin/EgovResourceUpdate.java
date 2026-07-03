package kr.go.egovframework.hyb.plugin;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;

import kr.go.egovframework.hyb.deviceapiapp.R;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import android.annotation.SuppressLint;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.AsyncTask;
import android.util.Log;

/**
 * @Class Name : EgovResourceUpdate
 * @Description : EgovResourceUpdate Class
 */

@SuppressLint("NewApi")
public class EgovResourceUpdate extends CordovaPlugin  {

	private final String ACTION_GET_APP_ID = "getAppId";
    private final String ACTION_UPDATE = "update";
    private final String ACTION_GET_APP_VERSION = "getAppVersion";
    private final String ACTION_GET_RESOURCE_VERSION = "getResourceVersion";

	private CallbackContext mCallbackContext;

    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) {

    	Log.d(this.getClass().getSimpleName(),">>>>> action = "+ action);
    	if (action.equals(ACTION_GET_APP_ID)) {

    		actionGetAppId(callbackContext);

    	} else if (action.equals(ACTION_GET_APP_VERSION)) {

        	actionGetAppVersion(callbackContext);

    	} else if (action.equals(ACTION_GET_RESOURCE_VERSION)) {

    		Context context = (Context) cordova.getActivity();
    		SharedPreferences settings = context.getSharedPreferences("plist", 0);
    		String resVersion = settings.getString("resVersion","");
    		String resDistDt = settings.getString("resDistDt","");
    		String resInstallDt = settings.getString("resInstallDt","");


    		JSONObject jsonObject = new JSONObject();
    		try {

    			if(resVersion.equals(null) || resVersion.equals("")){
        			PackageInfo i = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
        			resVersion = i.versionName;
        			Log.d(this.getClass().getSimpleName(),">>>>> resVersion 초기화 : "+ resVersion);
        		}

        		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        		if(resInstallDt.equals(null) || resInstallDt.equals("")){
        			resInstallDt = sdf.format(new Date(context.getPackageManager().getPackageInfo(context.getPackageName(), 0).firstInstallTime));
        			Log.d(this.getClass().getSimpleName(),">>>>> resInstallDt 초기화 : "+ resInstallDt);
        		}

    			jsonObject.put("resVersion", resVersion);
    			jsonObject.put("resDistDt", resDistDt);
    			jsonObject.put("resInstallDt", resInstallDt);

    		} catch (JSONException e1) {
    			e1.printStackTrace();
    		} catch (NameNotFoundException e) {}

    		callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, jsonObject));

    	} else if (action.equals(ACTION_UPDATE)) {

    		actionUpdate(data, callbackContext);
    	}


        return true;

    }

	private void actionGetAppVersion(CallbackContext callbackContext) {
		Context context = (Context) cordova.getActivity();
		String versionName = "";
		String versionCode = "";
		try {
			PackageInfo i = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
			versionName = i.versionName;
			versionCode = ""+i.versionCode;
		} catch(NameNotFoundException e) { }

		JSONObject jsonObject = new JSONObject();
		try {
			jsonObject.put("appVersion", versionName);
			jsonObject.put("appVersionCode", versionCode);
		} catch (JSONException e1) {
			e1.printStackTrace();
		}
		callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, jsonObject));
	}

	private void actionGetAppId(CallbackContext callbackContext) {
		Context context = (Context) cordova.getActivity();
		String appId = context.getPackageName();
		Log.d(this.getClass().getSimpleName(),">>>getPackageName = "+appId);

		JSONObject jsonObject = new JSONObject();
		try {
			jsonObject.put("appId", appId);
		} catch (JSONException e1) {
			e1.printStackTrace();
		}
		callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, jsonObject));
	}

	private void actionUpdate(JSONArray data, CallbackContext callbackContext) {
		mCallbackContext = callbackContext;
        Context context = (Context) cordova.getActivity();

    	JSONObject params = null;
    	String url = "";
        String streFileNm = "";
        String orignlFileNm = "";
        String targetPath = "";
        String resLastestVersion = "";
        String resVersionUpdDt = "";
        String resFileSha256 = "";

    	try {
			params = data.getJSONObject(1);
			url = data.getString(0);

	        streFileNm = params.getString("streFileNm");
	        orignlFileNm = params.getString("orignlFileNm");
	        targetPath = params.getString("targetPath");
	        resLastestVersion = params.getString("resLastestVersion");
	        resVersionUpdDt = params.getString("resVersionUpdDt");
	        if (params.has("resFileSha256") && !params.isNull("resFileSha256")) {
	        	resFileSha256 = params.getString("resFileSha256");
	        }

		} catch (JSONException e) {
			e.printStackTrace();
			requestCallBackContext(callbackContext, 1, "");
			return;
		}

        if (resFileSha256 == null || resFileSha256.trim().isEmpty()) {
        	requestCallBackContext(callbackContext, 10, "");
        	return;
        }

        Log.d(this.getClass().getSimpleName(),"url : "+ url);
        Log.d(this.getClass().getSimpleName(),"streFileNm : "+ streFileNm);
        Log.d(this.getClass().getSimpleName(),"orignlFileNm : "+ orignlFileNm);
        Log.d(this.getClass().getSimpleName(),"targetPath : "+ targetPath);
        Log.d(this.getClass().getSimpleName(),"resLastestVersion : "+ resLastestVersion);
        Log.d(this.getClass().getSimpleName(),"resVersionUpdDt : "+ resVersionUpdDt);


        try {
        	targetPath = resolveSecureTargetPath(context, targetPath);
        } catch (IOException e) {
        	requestCallBackContext(callbackContext, 12, "");
        	return;
        }
    	String downloadLocalPath = context.getCacheDir().toString()+"/"+sanitizeFileName(orignlFileNm);
        Log.d(this.getClass().getSimpleName(),"targetPath2 : "+ targetPath);
        Log.d(this.getClass().getSimpleName(),"downloadLocalPath : "+ downloadLocalPath);


    	Log.d(this.getClass().getSimpleName()," >>>>> INIT EgovResourceUpdate");
        String SERVER_URL = context.getString(R.string.SERVER_URL);

	    String downloadAssetFileUrl = SERVER_URL+url;
	    if (!isSecureDownloadUrl(context, downloadAssetFileUrl)) {
	    	requestCallBackContext(callbackContext, 4, "");
	    	return;
	    }

        new UpdateZipAssetFileAsync(context).execute(
        		downloadAssetFileUrl,
        		downloadLocalPath,
        		targetPath,
        		resLastestVersion,
        		resVersionUpdDt,
        		resFileSha256.trim().toLowerCase());
	}

    private static String resolveSecureTargetPath(Context context, String targetPath) throws IOException {
    	String defaultPath = context.getFilesDir().getCanonicalPath() + "/www";
    	if (targetPath == null || targetPath.equals("null") || targetPath.trim().isEmpty()) {
    		return defaultPath;
    	}
    	File canonicalTarget = new File(targetPath).getCanonicalFile();
    	File filesDir = context.getFilesDir().getCanonicalFile();
    	String canonicalPath = canonicalTarget.getPath();
    	String filesDirPath = filesDir.getPath();
    	if (!canonicalPath.equals(filesDirPath)
    			&& !canonicalPath.startsWith(filesDirPath + File.separator)) {
    		throw new SecurityException("Target path outside app files directory: " + targetPath);
    	}
    	return canonicalPath;
    }

    private static String sanitizeFileName(String fileName) {
    	if (fileName == null) {
    		return "resource_update.zip";
    	}
    	String sanitized = new File(fileName).getName();
    	if (sanitized.isEmpty()) {
    		return "resource_update.zip";
    	}
    	return sanitized;
    }

    private static boolean isSecureDownloadUrl(Context context, String downloadUrl) {
        try {
            URI uri = URI.create(downloadUrl.trim());
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return false;
            }
            if (!EgovInterfaceRequestValidator.isRequireHttps(context)) {
                return true;
            }
            return "https".equalsIgnoreCase(scheme);
        } catch (Exception e) {
            return false;
        }
    }

    private static String computeSha256Hex(String filePath) throws Exception {
    	MessageDigest digest = MessageDigest.getInstance("SHA-256");
    	FileInputStream fis = null;
    	try {
    		fis = new FileInputStream(filePath);
    		byte[] buffer = new byte[8192];
    		int read;
    		while ((read = fis.read(buffer)) != -1) {
    			digest.update(buffer, 0, read);
    		}
    	} finally {
    		if (fis != null) {
    			fis.close();
    		}
    	}

    	byte[] hash = digest.digest();
    	StringBuilder sb = new StringBuilder(hash.length * 2);
    	for (byte b : hash) {
    		sb.append(String.format("%02x", b & 0xff));
    	}
    	return sb.toString();
    }

    public class UpdateZipAssetFileAsync extends AsyncTask<String, String, String> {

    	private ProgressDialog mDlg;
    	private Context mContext;
    	private String mDownloadLocalPath;
    	private String mTargetPath;
    	private String mResVersion;
    	private String mResVersionUpdDt;
    	private String mResInstallDt;
    	private String mExpectedSha256;
    	private boolean mDownloadSucceeded;


    	public UpdateZipAssetFileAsync(Context context) {
    		mContext = context;
    	}

    	@Override
    	protected void onPreExecute() {
    		mDlg = new ProgressDialog(mContext);
    		mDlg.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
    		mDlg.setMessage("리소스 파일을 다운로드 중입니다.");
    		mDlg.show();
    		mDlg.setMax(100);

    		super.onPreExecute();
    	}

    	@Override
    	protected String doInBackground(String... params) {

    		int count = 0;
    		mDownloadSucceeded = false;

    		try {
    			Thread.sleep(100);
    			URL url = new URL(params[0].toString());
    			URLConnection connection = url.openConnection();

    			String paramDownloadLocalPath = params[1].toString();
    			String paramTargetPath = params[2].toString();
    			mResVersion = params[3].toString();
    			mResVersionUpdDt = params[4].toString();
    			mExpectedSha256 = params[5].toString();

    			Log.d(this.getClass().getSimpleName(), ">>> : paramDownloadLocalPath" + paramDownloadLocalPath);
    			Log.d(this.getClass().getSimpleName(), ">>> : paramTargetPath" + paramTargetPath);
    			mDownloadLocalPath = paramDownloadLocalPath;
    			mTargetPath = paramTargetPath;

    			connection.connect();

    			int lenghtOfFile = connection.getContentLength();
    			Log.d("ANDRO_ASYNC", "Lenght of file: " + lenghtOfFile);

    			InputStream input = new BufferedInputStream(url.openStream());
    			OutputStream output = new FileOutputStream(paramDownloadLocalPath);

    			byte data[] = new byte[1024];

    			long total = 0;

    			while ((count = input.read(data)) != -1) {
    				total += count;
    				if (lenghtOfFile > 0) {
    					publishProgress("" + (int) ((total * 100) / lenghtOfFile));
    				}
    				output.write(data, 0, count);
    			}

    			output.flush();
    			output.close();
    			input.close();
    			mDownloadSucceeded = true;

    		} catch (InterruptedException e) {
    			e.printStackTrace();
    			requestCallBackContext(mCallbackContext, 3, e.getMessage());
    		} catch (IOException e) {
    			e.printStackTrace();
    			requestCallBackContext(mCallbackContext, 3, e.getMessage());
    		}

    		return null;
    	}

    	@Override
    	protected void onProgressUpdate(String... progress) {
			mDlg.setProgress(Integer.parseInt(progress[0]));
    	}

    	@SuppressWarnings("deprecation")
    	@Override
    	protected void onPostExecute(String unused) {

    		if (!mDownloadSucceeded) {
    			mDlg.dismiss();
    			return;
    		}

    		Log.d(this.getClass().getSimpleName(),"Asset file unzip & Update");
    		try {
    			String actualSha256 = computeSha256Hex(mDownloadLocalPath);
    			if (!mExpectedSha256.equalsIgnoreCase(actualSha256)) {
    				new File(mDownloadLocalPath).delete();
    				requestCallBackContext(mCallbackContext, 11, "");
    				mDlg.dismiss();
    				return;
    			}

				EgovZip.unzip(mDownloadLocalPath, mTargetPath, false, mContext);
			} catch (Exception e) {
				e.printStackTrace();
				Log.d(this.getClass().getSimpleName(),"ERROR : unzip error!");
				new File(mDownloadLocalPath).delete();
				requestCallBackContext(mCallbackContext, 9, "");
				mDlg.dismiss();
				return;
			}

    		new File(mDownloadLocalPath).delete();
    		mDlg.dismiss();

    		SharedPreferences settings = mContext.getSharedPreferences("plist", 0);
    		SharedPreferences.Editor editor = settings.edit();
    		editor.putString("resVersion", mResVersion);
    		editor.putString("resDistDt", mResVersionUpdDt);
    		mResInstallDt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()).toString();
    		editor.putString("resInstallDt", mResInstallDt);
    		editor.commit();

    		requestCallBackContext(mCallbackContext, 0, "");
    	}
    }

    private void requestCallBackContext(CallbackContext callbackContext, int errCode, String addMessage) {

    	String errMessage = "";
    	switch(errCode) {
    	case 0:
    		errMessage = "업데이트가 성공적으로 반영되었습니다.";
    		break;
    	case 1:
    		errMessage = "파라미터에 오류가 있습니다.";
    		break;
    	case 2:
    		errMessage = "서버연결 실패";
    		break;
    	case 3:
    		errMessage = "통신오류 : ";
    		break;
    	case 4:
    		errMessage = "보안 다운로드 URL(HTTPS)만 허용됩니다.";
    		break;
    	case 9:
    		errMessage = "압축풀기 작업중 오류가 발생했습니다.";
    		break;
    	case 10:
    		errMessage = "리소스 무결성 검증값(SHA-256)이 필요합니다.";
    		break;
    	case 11:
    		errMessage = "다운로드한 리소스의 무결성 검증에 실패했습니다.";
    		break;
    	case 12:
    		errMessage = "허용되지 않은 압축 해제 경로입니다.";
    		break;
    	default:
    		errMessage = "기타 예외오류가 발생했습니다.";
    		break;
    	}

		JSONObject jsonObject = new JSONObject();
        try {
			jsonObject.put("resultCode", ""+errCode);
			jsonObject.put("resultMsg", errMessage+addMessage);

			Context context = (Context) cordova.getActivity();
			SharedPreferences settings = context.getSharedPreferences("plist", 0);
			jsonObject.put("resVersion", settings.getString("resVersion", ""));
			jsonObject.put("resDistDt", settings.getString("resDistDt", ""));
			jsonObject.put("resInstallDt", settings.getString("resInstallDt", ""));

		} catch (JSONException e1) {
			e1.printStackTrace();
		}
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, jsonObject));
    }

}
