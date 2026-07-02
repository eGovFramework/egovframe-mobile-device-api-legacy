/** 
 * @fileoverview 모바일 전자정부 하이브리드 앱 Network API 가이드 프로그램 JavaScript
 * JavaScript. 
 *
 * @author 서형주
 * @version 1.0 
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2015. 4. 20.   신용호 		iscroll5 적용
 * @ 2019. 9. 30.   신용호        앱버전이 서버에 없는 경우 메시지 추가
 */

/*********************************************************
 * A TAG 링크 컨트롤
 *********************************************************/


/**
 * A tag의 링크 변경
 * @returns 
 * @type 
 */
function fn_egov_init_hrefLink(){
    // 리소스 업데이트 플러그인 테스트
    $("#btnUpdate_LastestVersion").attr("href","javascript:fn_egov_update_lastestVersion();");
    $("#btnUpdate_update").attr("href","javascript:fn_egov_update_go();");
    $("#btnUpdate_goNewPage").attr("href","javascript:fn_egov_update_goNewPage();");
    
    runPlugin();
}

var appId;
var appVersion;
var resVersion;
var resDistDt;
var resInstallDt;
var resLastestVersion;
var orignlFileNm;
var streFileNm;
var resVersionUpdDt;
var resUpdateContent;
var resFileSha256;

var jsonresult;

function fn_egov_update_goNewPage() {
    //ßalert(cordova.file.documentsDirectory);
    //location.href=cordova.file.documentsDirectory+"/www/update.html";
    console.log(">>> Web Resource Directory: "+cordova.file.documentsDirectory);
    
    $("#ifUpdatepages").attr("src", cordova.file.documentsDirectory+"/www/update.html");
    $.mobile.changePage('#updateInfo', 'slide', false, false);
	infoScroll.refresh(); 
}

function runPlugin() {
    //alert(">>> Update Plugin");

	window.plugins.EgovResourceUpdate.getAppId(function(jsondata) {
        jsonresult = jsondata;
        console.log("jsondata.appId > "+jsondata.appId);
        appId = jsondata.appId;
	});
	window.plugins.EgovResourceUpdate.getAppVersion(function(jsondata) {
        jsonresult = jsondata;
        console.log("jsondata.appVersion > "+jsondata.appVersion);
        appVersion = jsondata.appVersion;
	});
	window.plugins.EgovResourceUpdate.getResourceVersion(function(jsondata) {
        jsonresult = jsondata;
        console.log("jsondata.resVersion > "+jsondata.resVersion);
        console.log("jsondata.resDistDt > "+jsondata.resDistDt);
        console.log("jsondata.resInstallDt > "+jsondata.resInstallDt);
        resVersion = jsondata.resVersion;
        resDistDt = jsondata.resDistDt;
        resInstallDt = jsondata.resInstallDt;       
        
	});
	
}

function fn_egov_update_go() {

	jConfirm('최신버전을 적용하시겠습니까?', '알림', 'c', function(r) {
        if (r == true) {
        	fn_egov_update_action();
        }
    });
	
}

function fn_egov_update_action() {
	
    var url = "/upd/ResourceUpdatefileDownload.do";
    
    console.log("member resLastestVersion : "+resLastestVersion);
    console.log("member orignlFileNm : "+orignlFileNm);
    console.log("member streFileNm : "+streFileNm);
    console.log("member resLastestVersion : "+resLastestVersion);
    console.log("member resVersionUpdDt : "+resVersionUpdDt);
        
    var params = {
        orignlFileNm :  orignlFileNm ,
        streFileNm : streFileNm,
        resLastestVersion : resLastestVersion,
        targetPath : null,
        resVersionUpdDt : resVersionUpdDt,
        resFileSha256 : resFileSha256};
    
    window.plugins.EgovResourceUpdate.update(url, params, function(jsondata) {

            jsonresult = jsondata;
            console.log("jsondata > "+jsondata);
            if (jsonresult.resultCode != "0") {
                jAlert('서버에서 파일전송에 문제가 있습니다.', '전송 오류', 'c');
                return;
            }

            resVersion = jsondata.resVersion;        
            resDistDt = jsondata.resDistDt;
            resInstallDt = jsondata.resInstallDt;
                        	 	    	 	
        	$.mobile.changePage('#main', 'slide', false, false);
        	infoScroll.refresh();
            jAlert('정상적으로 리소스가 다운로드 되었습니다.\n[업데이트 페이지로 이동하기] 메뉴에서 결과를 확인해 주세요.', '알림', 'c');
            	       
        }, function(result){
            alert("error > "+result);
        });

}

function fn_egov_update_lastestVersion() {
    
    //alert("REQ UPDATE INFO");
    console.log(">>>appId : "+appId);
    console.log(">>>device.platform : "+device.platform);
    
    var url = "/upd/ResourceUpdateVersionInfo.do";
    
    var params = {
        appId : appId ,
        osType : device.platform};
    
    window.plugins.EgovInterface.request(url, params, function(jsondata) {
            //var data = JSON.parse(jsondata);
            //alert("jsondata : "+jsondata);
            console.log("jsondata > "+jsondata);
            resultJson = jsondata;
            if (jsondata.result == null) {
                jAlert('서버에 현재 앱의 버전정보가 없습니다.', '전송 오류', 'c');
                return;
            }
         resLastestVersion = jsondata.result.resVersion;
         orignlFileNm = jsondata.result.orignlFileNm;
         streFileNm = jsondata.result.streFileNm;
         resVersionUpdDt = jsondata.result.updDt;
         resUpdateContent = jsondata.result.updateContent;
         resFileSha256 = jsondata.result.fileSha256;
         if (!resFileSha256) {
             jAlert('서버에서 리소스 무결성 검증값을 받지 못했습니다.', '전송 오류', 'c');
             return;
         }

            console.log("server resLastestVersion : "+jsondata.result.resVersion);
            console.log("server orignlFileNm : "+jsondata.result.orignlFileNm);
            console.log("server streFileNm : "+jsondata.result.streFileNm);
            console.log("server resVersionUpdDt : "+jsondata.result.updDt);
            console.log("server resUpdateContent : "+jsondata.result.updateContent);

            if(jsondata.resultState == "OK"){
             	$('.deviceInfo:eq(0)').html(resVersion);
            	$('.deviceInfo:eq(1)').html(resDistDt);
            	$('.deviceInfo:eq(2)').html(resInstallDt);    
            	$('.deviceInfo:eq(3)').html(resLastestVersion);
            	$('.deviceInfo:eq(4)').html(resVersionUpdDt);

                $.mobile.changePage('#deviceInfo', 'slide', false, false);
                infoScroll.refresh();;
                
                console.log("send push ok");
            }else{
                $("#alert_dialog").click( function() {
                 jAlert('데이터 전송 중 오류가 발생 했습니다.', '전송 오류', 'c');
                });
            }

        }, function(result){
         alert("error > "+result);
        });
    
}



/*********************************************************
 * iScroll 컨트롤 
 *********************************************************/

/** 디바이스 정보 리스트 페이지 iScroll */
var infoScroll;

/** 디바이스 정보 리스트 페이지 iScroll */
var detailScroll;

/** 디바이스 정보 리스트 페이지 iScroll */
var listScroll;


/**
 * iScroll 초기화 작업
 * @returns 
 * @type 
 */
function fn_egov_load_iScroll(){
    
    // Use this for high compatibility (iDevice + Android)
	var options = {
            scrollX: true,
            scrollbars: true
        }
	
	console.log("device.version >>> "+device.version);
	if (parseFloat(device.version)>=4.0) {
		options["click"] = true;
	}
	
    setTimeout(function () {

    	infoScroll = new IScroll("#infoWrapper", options);

    	detailScroll = new IScroll("#detailWrapper", options);
    	
    	listScroll = new IScroll("#listWrapper", options);
    	
    	document.addEventListener('touchmove', function (e) { e.preventDefault(); }, false);

    },500);


}

/*********************************************************
 * DeviceInfo VO 정의 
 *********************************************************/

/** 디바이스 정보  VO */
var deviceInfoVO = {
    sn : "",
    uuid : "",
    os : "",
    telno : "",
    strgeInfo : "",
    ntwrkDeviceInfo : "",
    pgVer : "",
    deviceNm : "",
    useyn : ""
}

/*********************************************************
 * 배터리 상태 모니터링
 *********************************************************/

/**
 * 배터리 관련 이벤트 등록 함수
 * @returns 
 * @type 
 */
function fn_egov_regist_batteryInvent(){
    window.addEventListener("batterystatus", fn_egov_onBatteryStatus, false);
    window.addEventListener("batterylow", fn_egov_onBatteryLow, false);
    window.addEventListener("batterycritical", fn_egov_onBatteryCritical, false);
}

/**
 * 배터리 상태 정보 콜백 함수
 * @returns 
 * @type 
 */
function fn_egov_onBatteryStatus(info) {
    // Handle the online event
    console.log("DeviceAPIGuide fn_egov_onBatteryStatus Success"); 
    //navigator.notification.alert("Level: " + info.level + "%, isPlugged: " + info.isPlugged);
}

/**
 * 배터리 상태가 Low일때 호출되는 콜백 함수
 * @returns 
 * @type 
 */
function fn_egov_onBatteryLow(info) {
    // Handle the battery low event
    console.log("DeviceAPIGuide fn_egov_onBatteryLow Success"); 
    navigator.notification.alert("Battery Level Low " + info.level + "%"); 
}

/**
 * 배터리 경고 상태일 때 호출되는 콜백 함수
 * @returns 
 * @type 
 */
function fn_egov_onBatteryCritical(info) {
    // Handle the battery critical event
    console.log("DeviceAPIGuide fn_egov_onBatteryCritical Success"); 
    navigator.notification.alert("Battery Level Critical " + info.level + "%\nRecharge Soon!"); 
}

/*********************************************************
 * Network 정보 조회
 *********************************************************/

/**
 * Network 정보 조회 function.
 * @returns 
 * @type  
 */
function fn_egov_get_networkInfo() {
    var networkState = navigator.connection.type;
    
    var states = {};
    states[Connection.UNKNOWN]  = 'Unknown connection';
    states[Connection.ETHERNET] = 'Ethernet connection';
    states[Connection.WIFI]     = 'WiFi connection';
    states[Connection.CELL_2G]  = 'Cell 2G connection';
    states[Connection.CELL_3G]  = 'Cell 3G connection';
    states[Connection.CELL_4G]  = 'Cell 4G connection';
    states[Connection.NONE]     = 'No network connection';
    
    return states[networkState];
    
}

/*********************************************************
 * Custom Plug-In 결과 조회
 *********************************************************/

/**
 * 전체 메모리 조회에 대한 성공 콜백 함수
 * @returns 
 * @type 
 */
function fn_egov_totalSpace_success(result){
    
    console.log("DeviceAPIGuide totalFileSystemSize success");
    deviceInfoVO.strgeInfo = result;
    $('.deviceInfo:eq(5)').html(deviceInfoVO.strgeInfo);
    
    return result.totalSpace;
}

/**
 * 디바이스 전화번호 조회에 대한 성공 콜백 함수
 * @returns 
 * @type 
 */
function fn_egov_deviceNumber_success(result){
    
    console.log("DeviceAPIGuide fn_egov_deviceNumber success");
    deviceInfoVO.telno = result;
    $('.deviceInfo:eq(3)').html(deviceInfoVO.telno);
    
    return result.telno;
}

/**
 * Custom Plug-In 조회에 실패 콜백 함수
 * @returns 
 * @type 
 */
function fn_egov_fail(error){
    console.log("DeviceAPIGuide fn_egov_fail : " + error);
}






/*********************************************************
 * 3G 여부 체크
 *********************************************************/

/**
 * 3G 여부 체크
 * @returns 
 * @type 
 */
var  is3GConfirmed = false;

function fn_is3GConfirmed(index){

    if(is3GConfirmed != true){
    
        jConfirm('Wi Fi 망이 아닐경우 추가적인 비용이 발생 할 수 있습니다. \n계속 하시겠습니까?.', '알림', 'c', function(r) {
            if (r == true) {
            	is3GConfirmed = true;
            } else {
                location.href=index;    
            }
        });
    }
}
