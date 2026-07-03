/** 
 * @fileoverview 디바이스API Media API 가이드 프로그램 JavaScript
 * JavaScript. 
 *
 * @author 이율경
 * @version 1.0 
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2015. 4. 20.   신용호 		iscroll5 적용 
 */

/*********************************************************
 * 공통
 *********************************************************/

/** 
 * RestService를 담당할 EgovInterface 객체 생성
 * @type EgovInterface
*/
var egovHyb = new EgovInterface();

/** 파일 업/다운로드 서버 URL */
var loadServer = "";

/** 서버 Context */
var context = "";

/** iscroll를 적용하기 위한 공통 */
var myScroll;

/** Media 관련 인스턴스 */
var mediaObj = null;

/** Media 녹음 관련 인스턴스 */
var mediaRecordObj = null;

/** Media 재생 위치 체크 인스턴스 */
var playTimer = null;

/** Media 녹음 타이머 인스턴스 */
var recordTimer = null;

/** Media 재생 길이 인스턴스 */
var timerDur = null;

/** Media 녹음 시간 */
var recTime = 0;

/** Media 관련 폴더 */
var directory = "egovMediaAPI";

/** 파일시스템 인스턴스 */
var entry;

/** 녹음 파일 URL */
var fileURL;

/** 날짜 포맷 형식 */
Date.prototype.format = function(format){
    
    var date = this;
    
    format = format.replace('YYYY', date.getFullYear());
    format = format.replace('MM',   zeroPad(date.getMonth() + 1));
    format = format.replace('DD',   zeroPad(date.getDate()));
    format = format.replace('hh',   zeroPad(date.getHours()));
    format = format.replace('mm',   zeroPad(date.getMinutes()));
    format = format.replace('ss',   zeroPad(date.getSeconds()));
    
    return format;
};

/** 날짜 포맷 형식 00 또는 0X */
function zeroPad(number) {
    
    return ( ( number < 10 ) ? "0" : "" ) + String(number);
    
}

/** 초 -> 시:분:초 */
function convertTime(number) {

    var hour;
    var minute;
    var second;
    
    if(parseInt(number) > -1) {
        
        hour = zeroPad(parseInt(number / 3600));
        minute = zeroPad(parseInt((number % 3600) / 60));
        second = zeroPad(parseInt(((number % 3600) % 60)));
    } else {
        
        hour = "00";
        minute = "00";
        second = "00";
    }
        
    return hour + ":" + minute + ":" + second;
}


/** HTML 출력용 XSS 이스케이프 */
function fn_egov_escapeHtml(value) {
    if (value == null) {
        return "";
    }
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&#34;")
        .replaceAll("'", "&#39;")
        .replaceAll("\\.", "&#46;")
        .replaceAll("%2E", "&#46;")
        .replaceAll("%2F", "&#47;");
}

/*********************************************************
 * HTML 관련 함수
 *********************************************************/

/**
 * 목록 조회 화면 출력
 * @returns 
 * @type 
 */
function fn_egov_displayList(xmldata) {
    
    var html = "";
    var listCount = $(xmldata).find("mediaAndroidAPIVOList").length;
    $(xmldata).find("mediaAndroidAPIVOList").each(function(){
        
                    var sn = $(this).find("sn").text();
                    var mdSj = fn_egov_escapeHtml($(this).find("mdSj").text());
                    var revivCo = fn_egov_escapeHtml($(this).find("revivCo").text());
                    
                    html += '<li>';
                    html += '     <a href="#" onclick="javascript:fn_egov_mediaInfoDetail(\'' + sn + '\')">';
                    html += '         <h3>' + mdSj + '</h3>';
                    html += '        <h3> 재생횟수 : ' + revivCo + '회</h3>';
                    html += '    </a>';
                    html += '</li>';        
                });
    
    $("#listMedia").html(html);
    
    loaded('#wrapper');
    $.mobile.loading("hide");
    $.mobile.changePage("#listPage", "slide", false, false);

    if (listCount < 1) {
        jAlert('서버에 저장된 미디어 목록이\n 없습니다.','알림','b');
    }

}

/**
 * 재생 화면 출력 (상세 조회)
 * @returns 
 * @type 
 */
function fn_egov_displayDetail(xmldata) {
    
    var sn = $(xmldata).find("sn").text();
    var mdSj = $(xmldata).find("mdSj").text();
    var streFileNm = $(xmldata).find("streFileNm").text();
    
    var html = "";
    
    fn_egov_mediaAPIConfig(sn);
    
    $("#mdSj").text(mdSj);
    fn_egov_mediaPlayInit();
    
    $.mobile.loading("hide");
    $.mobile.changePage($("#detailPage"));
}

/**
 * 하단 navbar 메뉴 출력
 * @returns 
 * @type 
 */
function fn_egov_mediaMenuDisplay(sel) {
    
   var html = "";
    
    html += '<div data-role="navbar"> <ul>';
    html += '    <li><a id="btnGoList" href="#listPage" data-icon="gear"  data-theme="b">목록</a></li>';
    
    if(sel == 'player') {
        
        html += '<li><a id="btnRecord" href="#" onclick="javascript:if(fn_egov_network_check(true)) { fn_egov_mediaRecordDisplayEvent(); }" data-icon="plus"  data-theme="b">녹음</a></li>';
    } else {
        
        html += '<li><a id="btnPlay" href="#" onclick="javascript:if(fn_egov_network_check(true)) { fn_egov_mediaPlayerDisplayEvent(); }" data-icon="plus"  data-theme="b">재생</a></li>';
    }
    
    html += '</ul> </div>'
    
    $("#detailFooter").html(html).trigger('create');
}

/*********************************************************
 * 이벤트 관련 함수
 *********************************************************/
$(function(){
		
	$(document).on("pageshow", "#mainPage", function(event, ui){
	        
	    if(myScroll != null) {
	    	
	    	myScroll.destroy();
	    }
	    
	    if(fn_egov_network_check(false)) {
	        		            
	        fn_egov_selectMediaList();
	    } else {
	            
	        navigator.app.backHistory();
	    }
	});
	    
	$(document).on("pagehide", "#mainPage", function(event, ui){
			    
	    $("#mediaList").empty();
	});
	
	$(document).on("pagebeforeshow", "#detailPage", function(event, ui){
	    
	    fn_egov_mediaPlayerDisplayEvent();
	    
	    setSliderChange ('mediaBar', function ( value ) {
	        
	        fn_egov_mediaSeekToEvent(value);
	    });
	});
	    
	$(document).on("pagehide", "#detailPage", function(event, ui){
	
	    $("#mdSj").text("");
	    $("#mediaPosition").text("00:00:00");
	    $("#playPencent").text("0%");
	    $("#mediaBar").val(0);
	    $("#mediaBar").slider('refresh');
	    
	    clearInterval(playTimer);
	    playTimer = null;
	    
	    if(mediaObj){
	    	mediaObj.release();
	    	mediaObj = null;
	    }
	    
	    fn_egov_mediaRecordStopEvent();
	});
	


});

/**
 * 재생 위치(range) 이동 이벤트
 * @returns 
 * @type 
 */
var setSliderChange = function ( elemID, handler ) {
    
    $('#' + elemID ).next().children('a').attr("id",elemID + "-slider");
    
    var sld = '#' + elemID + '-slider';
    $(sld).mouseup(function(event, ui) {
        
          handler($(this).attr("aria-valuenow"));
    });
    $(sld).touchend(function(event, ui) { 
        
          handler($(this).attr("aria-valuenow"));
    });
};

/**
 * 디바이스와 PhoneGap 준비 완료 이벤트
 * @returns 
 * @type 
 */
function DeviceAPIInit() {  
    
    fn_egov_deviceConfig();
    
    // file API를 이용하기 위한 setting.
    window.requestFileSystem(LocalFileSystem.PERSISTENT, 0, gotFS, fn_egov_error);
    
    if(mediaObj){
    	
    	mediaObj.release();
    }

}

/**
 * iScroll 적용
 * @returns 
 * @type 
 */
function loaded(scrollTarget) {
    
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

    	myScroll = new IScroll(scrollTarget, options);
    	myScroll.refresh();
    	
    	document.addEventListener('touchmove', function (e) { e.preventDefault(); }, false);

    },500);

}

/**
 * 어플리케이션 서버 설정
 * @returns 
 * @type 
 */
function fn_egov_deviceConfig() {
    
    egovHyb.geturl(function(serverContext){
        
        console.log("DeviceAPIGuide fn_egov_deviceConfig Success");
        
        context = serverContext;
        loadServer = serverContext;
        
        
        
        if(fn_egov_network_check(false)) {

        	$.mobile.changePage("#mainPage", "slide", false, false);
        } else {
            
            navigator.app.backHistory();
        }
    });
}

/**
 * Media 상세 정보 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaInfoDetail(sn) {
    
    networkCheck = false;
    if(fn_egov_network_check(true)) {

        fn_egov_selectMediaInfoDetail(sn);
    }
}

/**
 * Media 재생 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaPlayEvent() {
    
    $("#btnPause").show();
    $("#btnPlay").hide();
    
    fn_egov_mediaPlay();
    
    if (playTimer == null) {
	    playTimer = setInterval(function(){
	        mediaObj.getCurrentPosition(fn_egov_currentPositionSuccess, fn_egov_currentPositionError);
	    }, 1000);
    }
}

/**
 * Media 정지 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaStopEvent() {
    
    $("#mediaPosition").text("00:00:00");
    $("#playPencent").text("0%");
    $("#mediaBar").val(0);
    $("#mediaBar").slider('refresh');
    
    $("#btnPlay").show();
    $("#btnPause").hide();
    
    fn_egov_mediaStop();
    clearInterval(playTimer);
    playTimer = null;
}

/**
 * Media 일시정지 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaPauseEvent() {
    
    $("#btnPlay").show();
    $("#btnPause").hide();
    
    fn_egov_mediaPause();
    clearInterval(playTimer);
    playTimer = null;
}

/**
 * Media 재생 화면 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaPlayerDisplayEvent() {
    
    if(recordTimer != null) {
        
        jAlert("녹음을 정지해주십시오.", "알림", "b");
    } else {
    
        fn_egov_mediaMenuEvent('player');
        
        $("#recorder").hide();
        $("#player").show();
    }
}

/**
 * Media 녹음 화면 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaRecordDisplayEvent() {
    
    if(playTimer != null) {
        
        jAlert("Media 재생을\n정지해주십시오.", "알림", "b");
    } else {
        
        fn_egov_mediaMenuEvent('record');
        
        $("#player").hide();
        $("#recorder").show();
        $("#btnRecordStart").show();
        $("#btnRecordStop").hide();
    }
}

/**
 * Media 녹음 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaRecordStartEvent() {
    
    $("#btnRecordStop").show();
    $("#btnRecordStart").hide();
    
    var recordSj = fn_egov_mediaRecordStart();
    
    recTime = 0;
    $("#recordSj").text(recordSj);
    $("#recordPosition").text(convertTime(recTime));
    
    recordTimer = setInterval(function() {
        
        recTime = recTime + 1;
        $("#recordPosition").text(convertTime(recTime));
    } , 1000);
}

/**
 * Media 녹음 정지 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaRecordStopEvent() {
    
    $("#recordSj").text("");
    $("#recordPosition").text("00:00:00");
    
    $("#btnRecordStart").show();
    $("#btnRecordStop").hide();
    
    fn_egov_mediaRecordStop();
    clearInterval(recordTimer);
    recordTimer = null;
    
    jConfirm("서버에 전송하시겠습니까?", "알림", "b", function(result){
        if(result) {
        	
            $.mobile.loading("show");
            fn_egov_insertRecordFile();
        }
    });
}

/**
 * Media API 재생 위치 변화 이벤트
 * @returns
 * @type  
 */
function fn_egov_mediaSeekToEvent(position) {
    
    var max = $("#mediaBar").attr('max');

    if(parseInt(max) == parseInt(position)) {
    
        fn_egov_mediaStopEvent();
    } else {
        
        $("#mediaPosition").text(convertTime(position));
        $("#playPencent").text(parseInt(position*100/max) + "%");
        
        fn_egov_mediaSeekTo(position);
    }
}

/**
 * Media 메뉴 이벤트
 * @returns 
 * @type
 */
function fn_egov_mediaMenuEvent(sel) {
    
    fn_egov_mediaMenuDisplay(sel);
}

/*********************************************************
 * 성공/실패 관련 함수
 *********************************************************/

function fn_egov_success(r) {
    
    console.log("DeviceAPIGuide Media Config Success");
}

function fn_egov_currentPositionSuccess(position) {
    
    console.log("DeviceAPIGuide fn_egov_currentPositionSuccess Success");
    
    var max = parseInt(mediaObj.getDuration());
     
    if(parseInt(max) == parseInt(position)) {
        fn_egov_mediaStopEvent();
        
    }else if(position > -1){
        
        $("#mediaPosition").text(convertTime(position));
        
        $("#mediaBar").val(parseInt(position));
        $("#mediaBar").slider('refresh');
        
        $("#playPencent").text(parseInt(position*100/max) + "%");
    } 
}

function fn_egov_currentPositionError(e) {
    
    console.log("DeviceAPIGuide fn_egov_currentPositionError Error");
    
    jAlert("Media 오류.", "알림", "b", function(){
        
        fn_egov_mediaPauseEvent();
    });
}

function fn_egov_insertSuccess(r) {
    
    console.log("DeviceAPIGuide fn_egov_insertRecordFile request Completed");
    
    $.mobile.loading("hide");
    
    if(r.responseCode == 200 && r.response){
        
        jAlert("파일 업로드 완료", "알림", "b", function(){
            
            $.mobile.changePage($("#mainPage"));
        });
        
    }else{
        
        jAlert("파일 업로드 실패", "알림", "b");
    }
}

function fn_egov_error(error) {
    
    console.log("DeviceAPIGuide fn_egov_error by "+ error);
    
    $.mobile.loading("hide");
}

/*********************************************************
 * CRUD 관련 함수
 *********************************************************/

/**
 * 서버에 저장된 Media 목록 조회
 * @returns 
 * @type 
 */
function fn_egov_selectMediaList() {
    
    var url = "/mda/mediaInfoList.do";
    var acceptType = "xml";
    
    var params = {
                    mdCode : "media"
                };
    $.mobile.loading("show");
    egovHyb.post(url, acceptType, params, function(xmldata) {

        console.log("DeviceAPIGuide fn_egov_selectMediaList request Completed");
        
        fn_egov_displayList(xmldata);
    });
}

/**
 * Media 상세 정보 조회
 * @returns 
 * @type 
 */
function fn_egov_selectMediaInfoDetail(sn) {
    
    var url = "/mda/mediaInfoDetail.do";
    var acceptType = "xml";
    
    var params = {
                    sn : sn
                };
    $.mobile.loading("show");
    egovHyb.post(url, acceptType, params, function(xmldata) {
        
        console.log("DeviceAPIGuide fn_egov_selectMediaInfoDetail request Completed");
        
        fn_egov_displayDetail(xmldata);
    });
    
}

/**
 * 녹음 파일 등록
 * @returns 
 * @type 
 */
function fn_egov_insertRecordFile() {
    
	
	
    var file = fileURL.substr(fileURL.lastIndexOf('/') + 1);
    
    var options = new FileUploadOptions();
    options.fileKey = "file";
    options.fileName = file;
    options.mimeType = "audio/mp3";

    var params = {
            mdSj : file,
            uuid : encodeURI(device.uuid)
                };
    options.params = params;
    
    
    var ft = new FileTransfer();
    
    ft.upload(fileURL, loadServer + "/mda/mediaRecordUpload.do", fn_egov_insertSuccess, fn_egov_error, options);
}

/*********************************************************
 * Media API 제어 함수
 *********************************************************/

/**
 * Media API 설정
 * @returns
 * @type  
 */
function fn_egov_mediaAPIConfig(sn) {
    
    var src = context + "/mda/getMedia.do?sn=" + sn + "&uuid=" + encodeURIComponent(device.uuid);
    
    if(mediaObj) {
        
        mediaObj.release();
        mediaObj = null;
    }
    mediaObj = new Media(src, fn_egov_success, fn_egov_error);
}
/**
 * Media API 초기 재생
 * @returns
 * @type  
 */
function fn_egov_mediaPlayInit() {
    fn_egov_mediaPlayEvent();
    fn_egov_setMediaDuration();
}

/**
 * Media API 재생
 * @returns
 * @type  
 */
function fn_egov_mediaPlay() {
    
    mediaObj.play();
}

/**
 * Media API 정지
 * @returns
 * @type  
 */
function fn_egov_mediaStop() {
    if(mediaObj){
    	mediaObj.stop();
    }
}

/**
 * Media API 일시정지
 * @returns
 * @type  
 */
function fn_egov_mediaPause() {
    
    if(playTimer != null) {
    
        mediaObj.pause();
    }
}

/**
 * Media API 재생 위치 변화
 * @returns
 * @type  
 */
function fn_egov_mediaSeekTo() {
    
    var position = $("#mediaBar").val();
    
    mediaObj.seekTo(Number(position)*1000);
}

/**
 * Media API 녹음
 * @returns
 * @type  
 */
function fn_egov_mediaRecordStart() {
    
    entry.getDirectory(directory, {create: true, exclusive: false}, function(parent){}, fn_egov_error);
    
    var file = "Record_" + new Date().format("YYYYMMDDhhmmss") + ".mp3";
    var src =  file; //var src = "./" + directory + "/" + file;

    fileURL = cordova.file.externalRootDirectory + file; //entry.toURL() + "/" + directory + "/" + file;

    if(mediaRecordObj != null) {

        mediaRecordObj.release();
        mediaRecordObj = null;
    }
    
    mediaRecordObj = new Media(src, fn_egov_success, fn_egov_error);
    mediaRecordObj.startRecord();

    return file;
}

/**
 * Media API 녹음 정지
 * @returns
 * @type  
 */
function fn_egov_mediaRecordStop() {
    
    if(mediaRecordObj != null) {
        
        mediaRecordObj.stopRecord();
        mediaRecordObj.release();
        mediaRecordObj = null;
    }
}

/**
 * Stereaming 으로 인한 Media 길이 주기적 체크(4초)
 * @returns
 * @type  
 */
function fn_egov_setMediaDuration() {
    var counter = 0;
    timerDur = setInterval(function() {
        counter = counter + 50;
        if (counter > 2000) {
            
            clearInterval(timerDur);
            timerDur = null;
            fn_egov_error();
        }
        var dur = mediaObj.getDuration();
        if (dur > 0) {
            
            console.log("DeviceAPIGuide fn_egov_setMediaDuration Success");
            
           $("#mediaBar").attr('max', parseInt(dur));
           clearInterval(timerDur);
           timerDur = null;
        }
    } , 100);
}

/*********************************************************
 * File API 제어 함수
 *********************************************************/

/**
 * 파일 시스템 정보 획득
 * @returns
 * @type 
 */
function gotFS(fs) {
    
    console.log("DeviceAPIGuide gotFS Success");
    
    entry = fs.root;
}

function permissionSuccess(status) {
    console.log('### Check Permission');
    if( !status.hasPermission ) {
        permissionError();
    } else {
        console.log('### Permission is OK');
    }
}

function permissionError() {
    console.warn('### Permission is not turned on');
}
