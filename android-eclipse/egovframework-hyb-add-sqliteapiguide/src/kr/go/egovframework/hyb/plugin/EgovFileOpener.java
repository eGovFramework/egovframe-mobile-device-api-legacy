package kr.go.egovframework.hyb.plugin;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import kr.go.egovframework.hyb.deviceapiapp.R;

/**  
 * @Class Name : EgovFileOpener
 * @Description : EgovFileOpener Class
 * @Modification Information  
 * @
 * @  수정일       수정자                  수정내용
 * @ ---------   ---------   -------------------------------
 * @ 2016.07.11    장성호                  최초 작성
 * 
 * @author 디바이스 API 실행환경 개발팀
 * @since 2016. 06. 27
 * @version 1.0
 * @see
 * 
 *  Copyright (C) by MOI All right reserved.
 */

public class EgovFileOpener extends CordovaPlugin  {

	
    private final String FILE_DOWNLOAD = "fileDownload";
    
    private CallbackContext mCallbackContext;
	
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) {

    	Log.d(this.getClass().getSimpleName(),">>>>> fileOpener action = "+ action);
    	if (action.equals(FILE_DOWNLOAD)) {
    		actionUpdate(data, callbackContext);
    	}
    	
        return true;
    }


	private void actionUpdate(JSONArray data, CallbackContext callbackContext) {
		mCallbackContext = callbackContext;
        Context context = (Context) cordova.getActivity();

    	JSONObject params = null;
    	String url = "";
        String streFileNm = "";
        String orignlFileNm = "";
        String targetPath = "";
        
    	try {
			params = data.getJSONObject(1);
			url = EgovFileOpenerRequestValidator.normalizeDownloadUri(data.getString(0));
	        orignlFileNm = EgovFileOpenerRequestValidator.normalizeFileName(
	                params.getString("orignlFileNm"));
	        streFileNm = EgovFileOpenerRequestValidator.normalizeStoredFileName(
	                params.optString("streFileNm", ""));
	        targetPath = params.optString("targetPath", null);

	        String serverUrl = context.getString(R.string.SERVER_URL);
	        String downloadAssetFileUrl = EgovFileOpenerRequestValidator.buildDownloadUrl(
	                context, serverUrl, url);
	        File targetFile = EgovFileOpenerRequestValidator.resolveSecureTargetFile(
	                context, targetPath, orignlFileNm);

	        Log.d(this.getClass().getSimpleName(), "url : " + url);
	        Log.d(this.getClass().getSimpleName(), "streFileNm : " + streFileNm);
	        Log.d(this.getClass().getSimpleName(), "orignlFileNm : " + orignlFileNm);
	        Log.d(this.getClass().getSimpleName(), "targetPath : " + targetFile.getParent());

	        new FileOpenerFileAsync(context).execute(
	                downloadAssetFileUrl, targetFile.getParent(), targetFile.getName());
		} catch (JSONException e) {
			requestCallBackContext(callbackContext, 1, e.getMessage());
		} catch (IOException e) {
			requestCallBackContext(callbackContext, 1, e.getMessage());
		}
	}
    
    public class FileOpenerFileAsync extends AsyncTask<String, String, String> {

    	private ProgressDialog mDlg;
    	private Context mContext;
    	
    	public FileOpenerFileAsync(Context context) {
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
    		
    		try {
    			Thread.sleep(100);
    			URL url = new URL(params[0].toString());
    			URLConnection connection = url.openConnection();

    			String paramTargetPath = params[1].toString();
    			String paramOrignlFileNm = params[2].toString();

    			File targetFile = EgovFileOpenerRequestValidator.resolveSecureTargetFile(
    			        mContext, paramTargetPath, paramOrignlFileNm);

    			Log.d(this.getClass().getSimpleName(),
    			        ">>> : targetFile : " + targetFile.getAbsolutePath());

    			connection.connect();

    			int lenghtOfFile = connection.getContentLength();
    			Log.d("ANDRO_ASYNC", "Lenght of file: " + lenghtOfFile);

    			InputStream input = new BufferedInputStream(url.openStream());
    			OutputStream output = new FileOutputStream(targetFile);

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
    			
    		} catch (InterruptedException e) {
    			e.printStackTrace();
    			requestCallBackContext(mCallbackContext, 3, e.getMessage());
    		} catch (IOException e) {
    			e.printStackTrace();
    			requestCallBackContext(mCallbackContext, 3, e.getMessage());
    		} catch (JSONException e) {
    			requestCallBackContext(mCallbackContext, 1, e.getMessage());
    		}

    		return null;
    	}

    	@Override
    	protected void onProgressUpdate(String... progress) {    		
			mDlg.setProgress(Integer.parseInt(progress[0]));
    	}

 
    	@Override
    	protected void onPostExecute(String unused) {
    		
    		mDlg.dismiss();
    		
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
    	case 9:
    		errMessage = "압축풀기 작업중 오류가 발생했습니다.";
    		break;
    	default:
    		errMessage = "기타 예외오류가 발생했습니다.";
    		break;
    	}
    	
		JSONObject jsonObject = new JSONObject();
        try {
			jsonObject.put("resultCode", ""+errCode);
			jsonObject.put("resultMsg", errMessage+addMessage);
			
		} catch (JSONException e1) {
			e1.printStackTrace();
		}
        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, jsonObject));
    }
    
}
