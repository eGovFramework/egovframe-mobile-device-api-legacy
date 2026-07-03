/** 
 * @fileoverview 디바이스API Camera API 가이드 프로그램 JavaScript
 * JavaScript. 
 *
 * @author 이율경
 * @version 1.0 
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2015. 4. 20.   신용호 		iscroll5 적용 
 * @ 2024. 5. 02.   우시재		NSR 보안조치 ( 사진 제목에 XSS 방지 구현 추가 )
 */

/*********************************************************
 * 공통
 *********************************************************/

/** 
 * RestService를 담당할 EgovInterface 객체 생성
 * @type EgovInterface
*/
var egovHyb = new EgovInterface();

/** 이미지 경로 */
var image = "";

/** 파일 업/다운로드 서버 URL */
var loadServer = "";

/** 서버 Context */
var context = "";

/** 이미지 일련번호 */
var currentImageSn = "";

/** 이미지 수정여부 */
var modify = false;

/** iscroll를 적용하기 위한 공통 */
var myScroll;

/** 목록 페이지 위치 */
var pageIndex = 0;

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

/*********************************************************
 * HTML 관련 함수
 *********************************************************/

/**
 * 사진 상세정보 출력
 * @returns 
 * @type 
 */
function fn_egov_displayDetail(imageSrc, xmldata) {
    currentImageSn = $(xmldata).find("sn").text();
    var photoSj = $(xmldata).find("photoSj").text();
    
    $("#imageDetailSj").text("제목 : " + photoSj);
    $("#imageDetailView").attr('src', imageSrc);
    
}

/**
 * 사진 리스트 출력
 * @returns 
 * @type 
 */

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

function fn_egov_displayList(xmldata) {
    
    var html = "";
    
    $(xmldata).find("cameraAndroidAPIVOList").each(function(){
        
            var fileSn = $(this).find("fileSn").text();
                    var sn = $(this).find("sn").text();
            // 20240502 NSR 보안조치 ( 사진 제목에 XSS 방지 구현 추가 )
				    var photoSj = $(this).find("photoSj").text()
				                                            .replaceAll("&", "&amp;")
				                                            .replaceAll("<", "&lt;")
				                                            .replaceAll(">", "&gt;")
				                                            .replaceAll("\"", "&#34;")
				                                            .replaceAll("\'", "&#39;")
				                                            .replaceAll("\\.", "&#46;")
				                                            .replaceAll("%2E", "&#46;")
				                                            .replaceAll("%2F", "&#47;");
                    html += '<li>';
                    html += '     <a href="#" onclick="javascript:fn_egov_detailPhotoAlbum(\'' + sn + '\', \'' + fileSn + '\');">';
                    html += '         <img src="' + context + '/cmr/getImage.do?fileSn=' + fileSn + '&uuid=' + encodeURIComponent(device.uuid) + '" style="max-width: 100;" />';
                    html += '        <h3>' + photoSj + '</h3>';
                    html += '    </a>';
                    html += '</li>';        
                });
    
    if(pageIndex == 0) {
        
        $("#photoAlbumList").append(html).listview("refresh");
        loaded('#wrapper');
    } else {
        
        $("#photoAlbumList").append(html).listview("refresh");
        myScroll.refresh();
    }
    
    $.mobile.loading("hide");
}

/**
 * Android Back 버튼 클릭 이벤트 function.
 * @returns intro or signUp 화면에서 종료하고 나머지 화면에선 back 처리
 * @type
*/
function backKeyDown(e) { 
    console.log('Back Button Click!!');
    if($.mobile.activePage.is('#intro')){
        
      e.preventDefault();
      navigator.app.exitApp();

    }else{
        navigator.app.backHistory();
    }
}

/**
 * 사진 촬영 이미지 
 * @returns 
 * @type 
 */
function fn_egov_getPhotoAlbumInfo(imageURI) {
    
    console.log("DeviceAPIGuide fn_egov_getPhotoAlbumInfo Success");
    
    var html = "";
    image = imageURI;
    
    html += '<img src="' + image + '" style="max-width: 100;"> </img>';
    
    $("#imageView").html(html);
    
}


/*********************************************************
 * 이벤트 관련 함수
 *********************************************************/


$(function(){
    
    $.validator.setDefaults({
        submitHandler: function() {
            networkCheck = false;
            
            if(fn_egov_network_check(true)) {
                
                var html = $("#imageView").html();
                if(html == "") {
                	
                	jAlert("이미지를 선택해주십시오.", "알림", "b");
                } else {
                	
                	fn_egov_checkPhotoAlbum();
                }
            }
            
            return false;
        },
        invalidHandler: function(form, validator) {
            
        },
        showErrors:function(errorMap, errorList){
            
                if(this.numberOfInvalids()) {
                    
                    jAlert(errorList[0].message, "알림", "b");
                }
        }
    });
    
    $("#photoForm").validate();
    
        
    $(document).on("pageshow", "#listPhotoAlbum", function(event, ui){
        
        pageIndex = 0;
        var params = {
                currentPageIndex : pageIndex + ""
                    };
        
        if(fn_egov_network_check(false)) {
            
            fn_egov_selectPhotoAlbumList(params);
        } else {
            
            navigator.app.backHistory();
        }
    });
    
    $(document).on("pagehide", "#listPhotoAlbum", function(event, ui){
        
        $("#photoAlbumList").empty();
        myScroll.destroy();
    });
    
    $(document).on("pageshow", "#addPhotoAlbum", function(event, ui){
        
    });
    
    $(document).on("pageshow", "#detailPhotoAlbum", function(event, ui){

    });
    
    $(document).on("pagehide", "#detailPhotoAlbum", function(event, ui){
        
        currentImageSn = "";
    });
    
    $(document).on("pagehide", "#addPhotoAlbum", function(event, ui){
        
        currentImageSn = "";
        image = "";
        $("#photoSj").val("");
        $("#imageView").html("");
    });

});

/**
 * 디바이스와 PhoneGap 준비 완료 이벤트
 * @returns 
 * @type 
 */
function DeviceAPIInit() {  
    
    fn_egov_deviceConfig();
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
 * 사진 촬영 이벤트
 * @returns 
 * @type 
 */
function fn_egov_cameraPhotograph() {
    var Camera = navigator.camera;
    var cameraOption  = {
            quality: 50,
            destinationType : Camera.DestinationType.FILE_URI,
            sourceType : Camera.PictureSourceType.CAMERA,
            targetWidth: 200,
            targetHeight: 200
    };
    navigator.camera.getPicture(fn_egov_getPhotoAlbumInfo, fn_egov_error, cameraOption);
}

/**
 * 앨범 이벤트
 * @returns 
 * @type 
 */
function fn_egov_albumPhotograph() {
    var Camera = navigator.camera;
    var cameraOption  = {
            quality: 50,
            destinationType : Camera.DestinationType.FILE_URI,
            sourceType : Camera.PictureSourceType.PHOTOLIBRARY,
            targetWidth: 200,
            targetHeight: 200
    };
    navigator.camera.getPicture(fn_egov_getPhotoAlbumInfo, fn_egov_error, cameraOption);
}

/**
 * 사진 등록 이벤트
 * @returns 
 * @type 
 */
function fn_egov_savePhotoAlbum() {
    
    $("#photoForm").submit();
}

/**
 * 사진 상세보기 이벤트
 * @returns 
 * @type 
 */
function fn_egov_detailPhotoAlbum(sn, fileSn) {
    
    var imageSrc = context + '/cmr/getImage.do?fileSn=' + fileSn + '&uuid=' + encodeURIComponent(device.uuid);
    currentImageSn = sn;
    
    if(fn_egov_network_check(true)) {
        
        fn_egov_selectPhotoAlbumDetail(imageSrc);
    }
    
    $.mobile.changePage($("#detailPhotoAlbum"));
}

/**
 * 사진 삭제 이벤트
 * @returns 
 * @type 
 */
function fn_egov_deletePhotoAlbum() {
    
    jConfirm("삭제하시겠습니까?", "알림", "b", function(result){
        
        if(result) {
            
            fn_egov_deletePhotoAlbumInfo();
        }
    });
}

/**
 * 사진 메뉴 선택 이벤트
 * @returns 
 * @type 
 */
function fn_egov_selectPhoto(sel) {
    
    var html = '<div data-role="navbar"><ul>';
    if(sel == 'camera') {
        
        html += '<li><a href="#" id="btnCaptureImage" onclick="javascript:fn_egov_cameraPhotograph();" data-icon="star"  data-theme="b">사진 촬영</a></li>';
    } else {
        
        html += '<li><a href="#" id="btnMovePhotoAlbum" onclick="javascript:fn_egov_albumPhotograph();" data-icon="grid"  data-theme="b">갤러리</a></li>';
    }
    
    html += '<li><a href="#" id="btnRegistPhoto" onclick="javascript:fn_egov_savePhotoAlbum();" data-icon="gear"  data-theme="b">저장</a></li>';
    html += '</ul></div>';
    
    $("#addfooter").html(html).trigger('create');   
    
    $.mobile.changePage($("#addPhotoAlbum"));
}

/**
 * 더보기 이벤트
 * @returns 
 * @type 
 */
function fn_egov_event_addPhotoAlbumList() {
    
    pageIndex = pageIndex + 1;
    var params = { 
                    currentPageIndex : pageIndex + ""
                };
    if(fn_egov_network_check(false)) {
        
        fn_egov_selectPhotoAlbumList(params);
    }
}

/**
 * 페이지 검사 이벤트
 * @returns 
 * @type 
 */
function fn_egov_event_checkPage(xmldata) {
    
    var list = $(xmldata).find("cameraAndroidAPIVOList");
    if(list.length != 0) {
        
            fn_egov_displayList(xmldata);
    } else {
        
        if(pageIndex != 0) {
            
            jAlert("마지막 페이지입니다.", "알림", "b");
        } else {
            
            jAlert("정보가 없습니다.", "알림", "b");
        }
    }
}

/**
 * 어플리케이션 서버 설정
 * @returns 
 * @type 
 */
function fn_egov_deviceConfig() {
    
    $.mobile.loading("show");
    egovHyb.geturl(function(serverContext){
        
        console.log("DeviceAPIGuide fn_egov_deviceConfig Success");
        
        context = serverContext;
        loadServer = serverContext;
        
        $.mobile.loading("hide");
    });
}

/*********************************************************
 * 성공/실패 관련 함수
 *********************************************************/

function fn_egov_insertSuccess(r) {
    
    console.log("DeviceAPIGuide fn_egov_insertSuccess request Completed");
    
    $.mobile.loading("hide");
    
    if(r.responseCode == 200 && r.response){
        
        jAlert("파일 업로드 완료", "알림", "b", function(){
            
            $.mobile.changePage($("#main"));
        });
        
    }else{
        
        jAlert("파일 업로드 실패", "알림", "b");
    }
}

function fn_egov_error(error) {
    
    console.log("Error Function.");
    
    $.mobile.loading("hide");
    
    jAlert("Error!\n[" + error + "]", "알림", "b");
}

/*********************************************************
 * CRUD 관련 함수
 *********************************************************/

/**
 * 사진 상세 조회
 * @returns 
 * @type 
 */
function fn_egov_selectPhotoAlbumDetail(imageSrc) {
    
    var url = "/cmr/cameraPhotoAlbumDetail.do";
    var acceptType = "xml";
    
    var params = {
                    sn : currentImageSn
                    };
    
    egovHyb.post(url, acceptType, params, function(xmldata) {
        console.log("DeviceAPIGuide fn_egov_selectPhotoAlbumDetail request Completed");
        
        fn_egov_displayDetail(imageSrc, xmldata);
    });
}

/**
 * 사진 조회
 * @returns 
 * @type 
 */
function fn_egov_selectPhotoAlbumList(params) {
    
    var url = "/cmr/cameraPhotoAlbumList.do";
    var acceptType = "xml";
    
    egovHyb.post(url, acceptType, params, function(xmldata) {
        
        console.log("DeviceAPIGuide fn_egov_selectPhotoAlbumList request Completed");
        
        fn_egov_event_checkPage(xmldata);
    });
    
}


/**
 * 사진 등록
 * @returns 
 * @type 
 */
function fn_egov_insertPhotograph() {
    
    $.mobile.loading("show");
    
    var options = new FileUploadOptions();
    options.fileKey = "file";
    options.fileName = new Date().format("YYYYMMDDhhmmss") + ".jpg";
    options.mimeType = "image/jpeg";

    var params = {
                    photoSj : $("#photoSj").val(),
                    uuid : encodeURI(device.uuid)
                };
    options.params = params;
    

    var ft = new FileTransfer();
    
    ft.upload(image, loadServer + "/cmr/photoAlbumImageUpload.do", fn_egov_insertSuccess, fn_egov_error, options);
}

function fn_egov_updatePhotograph() {
    
    $.mobile.loading("show");
    
    var options = new FileUploadOptions();
    options.fileKey = "file";
    options.fileName = new Date().format("YYYYMMDDhhmmss") + ".jpg";
    options.mimeType = "image/jpeg";

    var ft = new FileTransfer();
    
    var params = {
                    sn : currentImageSn
                };
    
    options.params = params;
    ft.upload(image, loadServer + "/cmr/photoAlbumImageUpdate.do", fn_egov_insertSuccess, fn_egov_error, options);
}

/**
 * 사진 삭제
 * @returns 
 * @type 
 */
function fn_egov_deletePhotoAlbumInfo() {
    
    console.log("fn_egov_deletePhotoAlbumInfo Start.");
    
    var url = "/cmr/deleteCameraPhotoAlbum.do";
    var acceptType = "xml";
    
    var params = {
                    sn : currentImageSn
                };
    
    egovHyb.post(url, acceptType, params, function(xmldata) {
        console.log("DeviceAPIGuide fn_egov_deletePhotoAlbumInfo request Completed");
        
        jAlert("삭제되었습니다", "알림", "b", function(){
            
            $.mobile.changePage($("#listPhotoAlbum"), {changeHash:false});
        });
        
    });
}

/**
 * 사진 제목 중복 체크 및 분기
 * @returns 
 * @type 
 */
function fn_egov_checkPhotoAlbum() {
    
    console.log("fn_egov_checkPhotoAlbum Start.");
    
    var url = "/cmr/cameraPhotoAlbumCheck.do";
    var acceptType = "xml";
    var check = false;
    
    var params = {
                    photoSj : $("#photoSj").val()
                    };
    
    egovHyb.post(url, acceptType, params, function(xmldata) {
        
        console.log("DeviceAPIGuide fn_egov_checkPhotoAlbum request Completed");
        currentImageSn = $(xmldata).find("sn").text();
        
        if(currentImageSn != null && currentImageSn != "") {
            jConfirm("제목이 중복입니다.\n이미지를 수정하시겠습니까?", "알림", "b", function(result){
                
                if(result) {
                    fn_egov_updatePhotograph();
                }
            });
        } else {
            jConfirm("저장하시겠습니까?", "알림", "b", function(result){
                
                if(result) {
                    fn_egov_insertPhotograph();
                }
            });
        }
    });
    
    return check;
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
