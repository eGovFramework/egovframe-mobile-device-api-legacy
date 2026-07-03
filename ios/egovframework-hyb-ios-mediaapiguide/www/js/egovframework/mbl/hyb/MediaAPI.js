/**
 * @fileoverview 디바이스API Media API 가이드 프로그램 JavaScript
 * JavaScript.
 *
 * @author 이해성
 * @version 1.0
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2015. 6. 13.   신용호 		server URL EGovComModule에서 가져오도록 수정
 */

document.addEventListener("deviceready", onDeviceReady, false);

/*********************************************************
 * 공통
 *********************************************************/

/** 파일 업/다운로드 서버 URL */
//var loadServer = "http://192.168.100.140:8080/deviceWeb";
var loadServer = ""; // EGovComModule.h 에서 가져온다.

/** 서버 Context */
//var context = "http://192.168.100.140:8080/deviceWeb";
var context = ""; // EGovComModule.h 에서 가져온다.

/** iscroll를 적용하기 위한 공통 */
var myScroll = null;

/** Media 관련 인스턴스 */
var mediaObj = null;

/** Media 녹음 관련 인스턴스 */
var mediaRecordObj = null;

/** Media 재생 동작 여부 */
var playCheck = false;

/** Media 재생 위치 체크 인스턴스 */
var playTimer = null;

/** Media 녹음 타이머 인스턴스 */
var recordTimer = null;

/** Media 재생 길이 인스턴스 */
var timerDur = null;

/** Media 녹음 시간 */
var recTime = 0;

/** 파일시스템 인스턴스 */
var entry = null;

/** 녹음 파일 URL */
var fileURL = null;

/** 날짜 포맷 형식 */
Date.prototype.format = function(format)
{
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
function zeroPad(number)
{
    return ( ( number < 10 ) ? "0" : "" ) + String(number);
}

/** 초 -> 시:분:초 */
function convertTime(number)
{
    var hour;
    var minute;
    var second;
    
    if(parseInt(number) > -1)
    {
        hour = zeroPad(parseInt(number / 3600));
        minute = zeroPad(parseInt((number % 3600) / 60));
        second = zeroPad(parseInt(((number % 3600) % 60)));
    }
    else
    {
        hour = "00";
        minute = "00";
        second = "00";
    }
    
    return hour + ":" + minute + ":" + second;
}

/**
 * iscroll 이 로딩 되기전 모든 컨트롤이 다 로딩 되도록 기달려 주는 함수
 * @returns
 * @type
 */
function fn_egov_wait_iscroll(thisPage)
{
    // Use this for high compatibility (iDevice + Android)
    setTimeout(function ()
               {
               if(myScroll != null)
               {
               myScroll.destroy();
               }
               
               myScroll = new IScroll(thisPage, {
                                      scrollX: true,
                                      scrollbars: true,
                                      mouseWheel: true,
                                      interactiveScrollbars: true,
                                      shrinkScrollbars: 'scale',
                                      fadeScrollbars: true,
                                      click: true
                                      });
               
               document.addEventListener('touchmove', function (e) { e.preventDefault(); }, false);
               
               },
               500);
}

/*********************************************************
 * 초기화 관련 함수
 *********************************************************/

/**
 * 디바이스와 PhoneGap 준비 완료
 * @returns
 * @type
 */
function onDeviceReady()
{
    document.addEventListener('DOMContentLoaded', function () { setTimeout(loaded, 200); }, false);
    window.requestFileSystem(LocalFileSystem.PERSISTENT, 0, gotFS, fn_error);

    // 초기 이벤트 설정
    $(document).on("pageshow", "#mainList", function(event, ui) {
        if(context === null) {
            fn_egov_init_context();
        } else {
            fn_egov_show_mediaList();
        }
    });
    
    $(document).on("pagehide", "#mainList", function(event, ui) {
        $("#mainList").html("");
    });
    
    $(document).on("pagebeforeshow", "#detailPage", function(event, ui) {
        fn_mediaPlayerDisplayEvent();
        setSliderChange ('mediaBar', function ( value ) {
            fn_mediaSeekToEvent(value);
        });
    });
    
    $(document).on("pagehide", "#detailPage", function(event, ui) {
        $("#mdSj").text("");
        $("#mediaPosition").text("00:00:00");
        $("#playPencent").text("0%");
        $("#mediaBar").val(0);
        $("#mediaBar").slider('refresh');
        fn_mediaStop();
        clearInterval(playTimer);
        playTimer = null;

        mediaObj.release();
        mediaObj = null;

        fn_mediaRecordStopEvent();
    });
    
    EgovInterface.geturl(function(serverContext){
        console.log("DeviceAPIGuide serverContext Config Success");
        context = serverContext; // EGovComModule.h 에서 가져온다.
        loadServer = serverContext; // EGovComModule.h 에서 가져온다.
    });

    initPermissionScope();
}

function initPermissionScope() {
  var conf = {
      headerLabel: '권한 사용 알림!', //Hello
      bodyLabel: '앱사용시 필요한 권한에\n승인하여 주세요.', //Before you get started
      closeButtonTextColor: '#cccccc',
      closeButtonTitle: '닫기', //Return
      permissionButtonTextColor: '#30ab7d',
      permissionButtonBorderColor: '#30ab7d',
      closeOffset: '{-200, 0}',
      authorizedButtonColor: '#cccccc',
      unauthorizedButtonColor: '#c2262d',
      permissionButtonCornerRadius: '20',
      permissionLabelColor: '#ff5500',
      permissionButtonBorderWidth: '5',
      deniedCancelActionTitle: '취소', //Cancel
      deniedDefaultActionTitle: '설정', //Settings
      deniedAlertTitle: '권한', //Permission
      deniedAlertMessage: '권한을 승인하여 주세요!', //Please enable all the permissions
      disabledCancelActionTitle: '취소', //Cancel
      disabledDefaultActionTitle: '설정' //Settings
  };

  PermissionScope.init(conf);
  PermissionScope.addMicrophonePermission('마이크 사용이 가능하도록 승인하여 주십시요.');
  PermissionScope.show();
}


/** HTML 출력용 XSS 이스케이프 */
function fn_egov_escapeHtml(value) {
    if (value == null) {
        return "";
    }
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&#34;")
        .replace(/'/g, "&#39;")
        .replace(/\./g, "&#46;")
        .replace(/\//g, "&#47;");
}

/*********************************************************
 * HTML 관련 함수
 *********************************************************/

/**
 * 목록 조회 화면 출력
 * @returns
 * @type
 */
function fn_displayList(result)
{
    var html = "";
    var resultRows = result["mediaiOSAPIVOList"];
    
    if(resultRows.length > 0)
    {
        for ( var i = 0; i < resultRows.length; i++)
        {
            html += '<li>';
            html += ' 	<a onclick="fn_egov_open_mediaDetail(\'' + resultRows[i]["sn"] + '\')">';
            html += ' 		<h3>' + fn_egov_escapeHtml(resultRows[i]["mdSj"]) + '</h3>';
            html += '		<h3> 재생횟수 : ' + fn_egov_escapeHtml(resultRows[i]["revivCo"]) + '회</h3>';
            html += '	</a>';
            html += '</li>';
        }
    }
    
    $("#mediaList").html(html).listview("refresh");
    
    fn_egov_wait_iscroll('#wrapper');

    if (resultRows.length < 1) {
        jAlert('서버에 저장된 미디어\n 목록이 없습니다.','알림','b');
    }
}

/**
 * 재생 화면 출력 (상세 조회)
 * @returns
 * @type
 */
function fn_displayDetail(result)
{
    
    var html = "";
    
    var sn = result["sn"];
    var mdSj = result["mdSj"];
    var streFileNm = result["streFileNm"];
    $("#mdSj").text(mdSj);
    
    fn_egov_get_mediaDownload(sn,streFileNm);
    
}

/**
 * 하단 navbar 메뉴 출력
 * @returns
 * @type
 */
function fn_mediaMenuDisplay(sel)
{
    var html = "";
    
    html += '<div data-role="navbar"> <ul>';
    html += '<li><a id="btnGoList" href="#listPage" data-icon="gear"  data-theme="b">목록</a></li>';
    
    if(sel == 'player')
    {
        html += '<li><a id="btnRecord" href="#" onclick="fn_mediaRecordDisplayEvent();" data-icon="plus"  data-theme="b">녹음</a></li>';
    }
    else
    {
        html += '<li><a id="btnPlay" href="#" onclick="fn_mediaPlayerDisplayEvent();" data-icon="plus"  data-theme="b">재생</a></li>';
    }
    
    html += '</ul> </div>'
    
    $("#detailFooter").html(html).trigger('create');
    //$("#detailFooter").enhanceWithin();
}

/*********************************************************
 * 이벤트 관련 함수
 *********************************************************/

/**
 * 서버 Context 정보 얻어오기
 * @returns
 * @type
 */
function fn_egov_init_context()
{
    if(fn_egov_network_check(true))
    {
        var params = {};
        
        // $.mobile.loading("show");
        // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
        setTimeout(function()
                   {
                   fn_egov_sendto_server("/mda/htmlLoadiOS.do",params);
                   },
                   500);
    }
}

/**
 * 미디어 목록 요청 이벤트
 * @returns
 * @type
 */
function fn_egov_show_mediaList()
{
    if(fn_egov_network_check(false))
    {
        var params = {mdCode : "media"};
        
        $.mobile.loading("show");
        // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
        setTimeout(function()
                   {
                   fn_egov_sendto_server("/mda/mediaiOSInfoList.do",params);
                   },
                   500);
    }
}

/**
 * 미디어 파일 다운로드 요청 이벤트
 * @returns
 * @type
 */
function fn_egov_get_mediaDownload(sn, fileName)
{
    if(fn_egov_network_check(true))
    {
        var fileType = fileName.substr(fileName.lastIndexOf('.')+1);
        var fileTransfer = new FileTransfer();
        console.log("1.entry.nativeURL >>> "+entry.nativeURL);
        var myPath = entry.nativeURL;
        var mediaFileName = "Media."+fileType;
        fileTransfer.download(
                              loadServer + "/mda/getMediaiOS.do?sn=" + sn + "&uuid=" + encodeURIComponent(device.uuid),
                              entry.nativeURL + mediaFileName,
                              function(entry)
                              {
                              console.log("DeviceAPIGuide fn_egov_get_mediaDownload Success");
                              $.mobile.loading("hide");
                              console.log("2.entry.fullPath >>>" + mediaFileName);
                              fn_mediaAPIConfig("documents://"+mediaFileName);
                              fn_mediaPlayInit();
                              fn_setMediaDuration();
                              console.log("LocalFileSystem.TEMPORARY : "+ LocalFileSystem.TEMPORARY);
                              $.mobile.changePage($("#detailPage"));
                              },
                              function(error)
                              {
                              console.log("DeviceAPIGuide fn_egov_get_mediaDownload error");
                              console.log("target : " + error.target + " source : " + error.source + " code : "+error.code);
                              $.mobile.loading("hide");
                              });
    }
}

/**
 * 선택된 미디어 상세 정보 요청 이벤트
 * @returns
 * @type
 */
function fn_egov_open_mediaDetail(sn)
{
    if(fn_egov_network_check(false))
    {
        var params = {
            sn : sn
        };
        
        $.mobile.loading("show");
        // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
        setTimeout(function()
                   {
                   fn_egov_sendto_server("/mda/mediaiOSInfoDetail.do",params);
                   },
                   500);
    }
}

/**
 * Media 재생 이벤트
 * @returns
 * @type
 */
function fn_mediaPlayEvent()
{
    $("#btnPause").show();
    $("#btnPlay").hide();
    
    fn_mediaPlay();
    
    playTimer = setInterval(function()
                            {
                            mediaObj.getCurrentPosition(fn_currentPositionSuccess, fn_currentPositionError);
                            }, 1000);
}

/**
 * Media 정지 이벤트
 * @returns
 * @type
 */
function fn_mediaStopEvent()
{
    $("#mediaPosition").text("00:00:00");
    $("#playPencent").text("0%");
    $("#mediaBar").val(0);
    $("#mediaBar").slider('refresh');
    
    $("#btnPlay").show();
    $("#btnPause").hide();
    
    fn_mediaStop();
    clearInterval(playTimer);
    playTimer = null;
}

/**
 * Media 일시정지 이벤트
 * @returns
 * @type
 */
function fn_mediaPauseEvent()
{
    $("#btnPlay").show();
    $("#btnPause").hide();
    
    fn_mediaPause();
    clearInterval(playTimer);
    playTimer = null;
}

/**
 * Media 재생 화면 이벤트
 * @returns
 * @type
 */
function fn_mediaPlayerDisplayEvent()
{
    if(recordTimer != null)
    {
        jAlert("녹음을 정지해주십시오.", "알림", "b");
    }
    else
    {
        fn_mediaMenuDisplay('player');
        $("#recorder").hide();
        $("#player").show();
    }
}

/**
 * Media 녹음 화면 이벤트
 * @returns
 * @type
 */
function fn_mediaRecordDisplayEvent()
{
    if(playTimer != null)
    {
        jAlert("Media 재생을\n정지해주십시오.", "알림", "b");
    }
    else
    {
        fn_mediaMenuDisplay('record');
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
function fn_mediaRecordStartEvent()
{
    $("#btnRecordStop").show();
    $("#btnRecordStart").hide();
    var recordSj = fn_mediaRecordStart();
    
    recTime = 0;
    $("#recordSj").text(recordSj);
    $("#recordPosition").text(convertTime(recTime));
    
    recordTimer = setInterval(function()
                              {
                              recTime = recTime + 1;
                              $("#recordPosition").text(convertTime(recTime));
                              } , 1000);
}

/**
 * Media 녹음 정지 이벤트
 * @returns
 * @type
 */
function fn_mediaRecordStopEvent()
{
    $("#recordSj").text("");
    $("#recordPosition").text("00:00:00");
    
    $("#btnRecordStart").show();
    $("#btnRecordStop").hide();
    
    fn_mediaRecordStop();
    clearInterval(recordTimer);
    recordTimer = null;
    
    jConfirm("서버에 전송하시겠습니까?", "알림", "b",
             function(result)
             {
             if(result)
             {
             $.mobile.loading("show");
             
             if(fn_egov_network_check(true))
             {
             var file = fileURL.substr(fileURL.lastIndexOf('/') + 1);
             
             var options = new FileUploadOptions();
             options.fileKey = "file";
             options.fileName = file;
             options.mimeType = "audio/wav";
             
             var params = {};
             options.params = params;
             
             var ft = new FileTransfer();
             var serverPath = loadServer + "/mda/mediaiOSRecordUpload.do?mdSj="+encodeURIComponent(file)+"&uuid="+ encodeURI(device.uuid);
             ft.upload(fileURL, serverPath, fn_insertSuccess, fn_error, options);
             }
             }
             });
}

/**
 * Media API 재생 위치 변화 이벤트
 * @returns
 * @type
 */
function fn_mediaSeekToEvent(position)
{
    var max = $("#mediaBar").attr('max');
    
    if(parseInt(max) == parseInt(position))
    {
        fn_mediaStopEvent();
    }
    else
    {
        if(isNaN(parseInt(max)) || isNaN(parseInt(position)))
        {
            return;
        }
        
        $("#mediaPosition").text(convertTime(position));
        $("#playPencent").text(parseInt(position*100/max) + "%");
        
        fn_mediaSeekTo();
    }
}

/**
 * 재생 위치(range) 이동 이벤트
 * @returns
 * @type
 */
var setSliderChange = function ( elemID, handler )
{
    $('#' + elemID ).next().children('a').attr("id",elemID + "-slider");
    var sld = '#' + elemID + '-slider'
    $(sld).mouseup(function(event, ui)
                   {
                   handler($(this).attr("aria-valuenow"));
                   });
    $(sld).touchend(function(event, ui)
                    {
                    handler($(this).attr("aria-valuenow"));
                    });
};


/*********************************************************
 * 통신
 *********************************************************/

/**
 *  서버로 전송
 * @returns
 * @type
 */
function fn_egov_sendto_server(serviceName, params)
{
    EgovInterface.submitAsynchronous(
                                     [params, serviceName],
                                     function(result)
                                     {
                                     var str = result["resultState"];
                                     if(str === "OK")
                                     {
                                     if(serviceName === "/mda/mediaiOSInfoList.do")
                                     {  // 서버에 저장된 Media 목록
                                     $.mobile.changePage($("#listPage"));
                                     fn_displayList(result);
                                     }
                                     else if(serviceName === "/mda/htmlLoadiOS.do")
                                     {   // 서버 초기 설정 정보
                                     //context = result["serverContext"];
                                     //loadServer = result["downloadContext"];
                                     fn_egov_show_mediaList();
                                     }
                                     else if(serviceName === "/mda/mediaiOSInfoDetail.do")
                                     {   // 선태된 미디어 상세정보 요청
                                     var mediaiOSFileVO = result["mediaiOSAPIFileVO"];
                                     fn_displayDetail(mediaiOSFileVO);
                                     return;
                                     }
                                     else if(serviceName === "/mda/getMediaiOS.do")
                                     {   // 미디어 파일 다운로드
                                     
                                     }
                                     
                                     console.log("DeviceAPIGuide fn_egov_sendto_server Response Completed");
                                     }
                                     else
                                     {
                                     console.log("DeviceAPIGuide fn_egov_sendto_server Response Failed");
                                     jAlert('Server 내부 장애.', '알림', 'c');
                                     }
                                     $.mobile.loading("hide");
                                     },
                                     function(error)
                                     {
                                     $.mobile.loading("hide");
                                     console.log("DeviceAPIGuide fn_egov_sendto_server Request Failed");
                                     jAlert('Request error. 서버가 종료되었거나 \n통신이 원활하지 않습니다.', '알림', 'c');
                                     });
}


/*********************************************************
 * Media API 제어
 *********************************************************/

/**
 * Media API 설정
 * @returns
 * @type
 */
function fn_mediaAPIConfig(filePath)
{
    if(mediaObj != null)
    {
        mediaObj.release();
        mediaObj = null;
    }
    mediaObj = new Media(filePath, fn_success, fn_error);
    
}

/**
 * Media API 초기 재생
 * @returns
 * @type
 */
function fn_mediaPlayInit()
{
    $("#btnPause").show();
    $("#btnPlay").hide();
    
    fn_mediaPlayEvent();
}

/**
 * Media API 재생
 * @returns
 * @type
 */
function fn_mediaPlay()
{
    mediaObj.play();
}

/**
 * Media API 정지
 * @returns
 * @type
 */
function fn_mediaStop()
{
    playCheck = false;
    mediaObj.stop();
}

/**
 * Media API 일시정지
 * @returns
 * @type
 */
function fn_mediaPause()
{
    if(playTimer != null)
    {
        mediaObj.pause();
    }
}

/**
 * Media API 재생 위치 변화
 * @returns
 * @type
 */
function fn_mediaSeekTo()
{
    var position = $("#mediaBar").val();
    if(isNaN(position) || position < 0)
    {
        return;
    }
    mediaObj.seekTo(Number(position)*1000);
}

/**
 * Media API 녹음
 * @returns
 * @type
 */
function fn_mediaRecordStart()
{
    var file = "Record_" + new Date().format("YYYYMMDDhhmmss") + ".wav";
    var src = null;
    entry.getFile(file, {create: true, exclusive: false},
                  function(entry)
                  {
                  console.log("DeviceAPIGuide fn_mediaRecordStart Success");
                  src = entry.nativeURL;
                  console.log("DeviceAPIGuide fn_mediaRecordStart entry : " + src);
                  
                  if(mediaRecordObj != null)
                  {
                  mediaRecordObj.release();
                  mediaRecordObj = null;
                  }
                  
                  
                  mediaRecordObj = new Media("documents://"+file, fn_success, fn_error);
                  //mediaRecordObj.filetype = "mp3"
                  mediaRecordObj.startRecord();
                  }, fn_error);
    
    fileURL = entry.nativeURL + file;
    return file;
}

/**
 * Media API 녹음 정지
 * @returns
 * @type
 */
function fn_mediaRecordStop()
{
    if(mediaRecordObj != null)
    {
        alert("녹음 중지");
        mediaRecordObj.stopRecord();
        mediaRecordObj.release();
        mediaRecordObj = null;
    }
}

/**
 * Stereaming 으로 인한 Media 길이 정보 얻기
 * @returns
 * @type
 */
function fn_setMediaDuration()
{
    var counter = 0;
    timerDur = setInterval(function()
                           {
                           counter = counter + 50;
                           if (counter > 2000)  // 4초 안에 플레이 시작이 되어야 하는걸로 설정.
                           {
                           clearInterval(timerDur);
                           timerDur = null;
                           fn_error();
                           }
                           var dur = mediaObj.getDuration();    // mediaObj.play(); 가 실행된 이후에만 값을 얻어 올수 있음.
                           if (dur > 0)
                           {
                           $("#mediaBar").attr('max', parseInt(dur));
                           clearInterval(timerDur);
                           timerDur = null;
                           }
                           } , 100);
}


/*********************************************************
 * 성공/실패 관련 함수
 *********************************************************/

function fn_success(r)
{
    console.log("DeviceAPIGuide fn_success Success");
}

function fn_currentPositionSuccess(position)
{
    console.log("DeviceAPIGuide fn_currentPositionSuccess Success");
    
    var max = $("#mediaBar").attr('max');
    
    if(parseInt(max) == parseInt(position))
    {
        fn_mediaStopEvent();
    }
    else
    {
        $("#mediaPosition").text(convertTime(position));
        $("#mediaBar").val(parseInt(position));
        $("#mediaBar").slider('refresh');
        $("#playPencent").text(parseInt(position*100/max) + "%");
    }
}

function fn_currentPositionError(e)
{
    console.log("DeviceAPIGuide fn_currentPositionError Error");
    jAlert("Media 오류.", "알림", "b",
           function()
           {
           fn_mediaPauseEvent();
           });
}

function fn_insertSuccess(r)
{
    console.log("DeviceAPIGuide fn_insertSuccess Success");
    
    $.mobile.loading("hide");
    if(r.responseCode == 200 && r.response)
    {
        jAlert("파일 업로드 완료", "알림", "b",
               function()
               {
               $.mobile.changePage($("#mainPage"));
               });
    }
    else
    {
        jAlert("파일 업로드 실패", "알림", "b");
    }
}

function fn_error(error)
{
    console.log("DeviceAPIGuide fn_error Error");
    console.log("errorCode : "+error.code+" errorMessage : "+error.message);
    
    $.mobile.loading("hide");
    jAlert("Media 오류.", "알림", "b");
}


/*********************************************************
 * File API 제어 함수
 *********************************************************/

/**
 * 파일 시스템 정보 획득
 * @returns
 * @type
 */
function gotFS(fs)
{
    entry = fs.root;
}
