/** 
 * 모바일 전자정부 하이브리드 앱 Camera API 가이드 프로그램 JavaScript
 * JavaScript. 
 *
 * @author 이해성
 * @version 1.0 
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2015. 6. 13.   신용호 		server URL EGovComModule에서 가져오도록 수정
 */

/*********************************************************
 * 초기화 관련 함수
 *********************************************************/

/** 서버 URL */
//var context = "http://192.168.100.140:8080/deviceWeb";
var context = ""; // EGovComModule.h 에서 가져온다.

/** 파일 업/다운로드 서버s URL */
//var downloadContext = null;
//var downloadContext = "http://10.211.55.5:8080/deviceWeb";
var downloadContext = ""; // EGovComModule.h에서 가져온다.




/** 이미지 경로 */
var image = "";

/** 이미지 일련번호 */
var currentImageSn = "";

/** 이미지 수정여부 */
var modify = false;

/** iscroll 객체 */
var myScroll = null;

/** 사진목록 리스트 배열 */
var ImageArray = null;

document.addEventListener("deviceready", onDeviceReady, false);

function onDeviceReady() 
{
    document.addEventListener('DOMContentLoaded', function () { setTimeout(loaded, 200); }, false);
    fn_egov_init_context();

    $.validator.setDefaults(
    { 
        onkeyup:false,
        onclick:false,
        onfocusout:false,

        submitHandler:function() 
        {
            var html = $("#imageView").html();
            if(html == "") 
            {
                jAlert("이미지를 선택해주십시오.", "알림", "b");
            }
            else
            {
                if(fn_egov_network_check(false))        // 통신 이벤트 발생시 3G 사용자 승인여부 판단
                {
                    var params = {
                        photoSj : $("#photoSj").val(),
                        uuid : device.uuid
                    };

                    $.mobile.loading("show");
                    // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
                    setTimeout(function()
                               {
                                   fn_egov_sendto_server("/cmr/cameraPhotoAlbumCheckiOS.do",params);
                               },
                               500);
                }
            }
            return false;
        },
        invalidHandler:function(form, validator) 
        {
        },
        showErrors:function(errorMap, errorList)
        {
            if(this.numberOfInvalids())
            {
                jAlert(errorList[0].message, "알림", "b");
            }
        }
    });

    $("#photoForm").validate();
    $("#listPhotoAlbum").on("pageshow", 
                              function(event, ui)
                              {
                                  fn_egov_wait_iscroll('#wrapper');
                              });
    
    $("#detailPhotoAlbum").on("pageshow", 
                                function(event, ui)
                                {
                                    fn_egov_wait_iscroll('#wrapper_imageDetail');
                                });

    $("#listPhotoAlbum").on("pagehide", 
                              function(event, ui)
                              	{
    								ImageArray = null;
    								
    								$("#photoAlbumList").html("");
                              	});

    $("#detailPhotoAlbum").on("pagehide", 
                                function(event, ui)
                                {
                                    currentImageSn = "";
                                });
  
    $("#addPhotoAlbum").on("pagehide", 
                             function(event, ui)
                             {
                                 currentImageSn = "";
                                 image = "";
                                 $("#photoSj").val("");
                                 $("#imageView").html("");
                             });

    EgovInterface.geturl(function(serverContext){
        
        console.log("DeviceAPIGuide serverContext Config Success");
        
        context = serverContext; // EGovComModule.h 에서 가져온다.
        downloadContext = serverContext; // EGovComModule.h 에서 가져온다.
        //alert("serverContext : "+ serverContext);
    });

}


/*********************************************************
 * html 관련 함수
 *********************************************************/

/**
 * 사진 메뉴 (직접 촬영, 앨범에서 선택) 선택 이벤트
 * @returns 
 * @type 
 */
function fn_selectPhoto(sel) 
{
    if(context === null)
    {
        fn_egov_init_context();
        return;
    }
	
    var html = '<div data-role="navbar"><ul>';
    if(sel == 'camera') 
    {
        html += '<li><a href="#" id="btnCaptureImage" onclick="fn_egov_capture_photo(\'camera\')" data-icon="star"  data-theme="b">사진 촬영</a></li>';
    }
    else 
    {
        html += '<li><a href="#" id="btnMovePhotoAlbum" onclick="fn_egov_capture_photo(\'album\')" data-icon="grid"  data-theme="b">갤러리</a></li>';
    }

    html += '<li><a href="#" id="btnRegistPhoto" onclick="fn_save_PhotoAlbum();" data-icon="gear" data-theme="b">저장</a></li>';
    html += '</ul></div>';
    $("#addfooter").html(html).trigger('create');   
    $.mobile.changePage($("#addPhotoAlbum"));
}

/**
 * 사진 리스트 출력
 * @returns 
 * @type 
 */
function fn_egov_displayList() 
{
    var html = "";

    if(ImageArray.length > 0)
    {
        for ( var i = 0; i < ImageArray.length; i++) 
        {
            var photoSj = (ImageArray[i]["photoSj"] || "")
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&#34;")
                .replace(/'/g, "&#39;")
                .replace(/\./g, "&#46;")
                .replace(/\//g, "&#47;");
            html += '<li>';
            html += ' 	<a href="#" onclick="fn_detailPhotoAlbum(\'' + ImageArray[i]["sn"] + '\');">';
            html += ' 		<img src="' + context + '/cmr/getImageiOS.do?fileSn=' + ImageArray[i]["fileSn"] + '&uuid=' + encodeURIComponent(device.uuid) + '" style="max-width: 100;" />';
            html += '		<h3>' + photoSj + '</h3>';
            html += '	</a>';
            html += '</li>';
        }
    }
	
    $("#photoAlbumList").html(html).listview("refresh");
    if (myScroll != null) myScroll.refresh();
}

/**
 * 사진 리스트 로컬 배열에 추가
 * @returns 
 * @type 
 */
function fn_egov_add_imageList(result) 
{
    var html = "";
    var resultRows = result["cameraiOSAPIVOList"];
    if(resultRows.length > 0)
    {
        if(ImageArray === null)
        {
            ImageArray = resultRows;
        }
        else
        {
            for ( var i = 0; i < resultRows.length; i++) 
            {
                ImageArray.push(resultRows[i]);
            }
        }
    }
    else
    {
        jAlert('서버에 저장된 사진\n 목록이 없습니다.','알림','b');
        return;
    }
    fn_egov_displayList();
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
        
        $.mobile.loading("show");
        // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
        setTimeout(function()
                   {
                       fn_egov_sendto_server("/cmr/htmlLoadiOS.do",params);
                   }, 
                   500);
    }
}

/**
 * 사진 등록 이벤트
 * @returns 
 * @type 
 */
function fn_save_PhotoAlbum() 
{
    $("#photoForm").submit();
}

/**
 * 사진 서버로 전송 성공시 
 * @returns 
 * @type 
 */
function fn_insertSuccess(r) 
{	
    console.log("DeviceAPIGuide fn_insertSuccess");
    $.mobile.loading("hide");

    if(r.responseCode == 200 && r.response)
    {
        jAlert("파일 업로드 완료", "알림", "b", 
               function()
               {
                   $.mobile.changePage($("#main"));
               });
    }
    else
    {
        jAlert("파일 업로드 실패", "알림", "b");
    }
}

/**
 * 사진 서버로 전송 실패시 
 * @returns 
 * @type 
 */
function fn_error(error) 
{	
    console.log("DeviceAPIGuide fn_error");

    $.mobile.loading("hide");

    jAlert("Error!\n[" + message + "]", "알림", "b");
}

/**
 * Camera 사진 정보 목록 서버에서 요청
 * @returns
 * @type 
 */
function fn_egov_show_ImgList()
{
    if(fn_egov_network_check(false))        // 통신 이벤트 발생시 3G 사용자 승인여부 판단
    {
        var params = null;
        if(ImageArray === null)
        {
            params = {pageIndex:1};        
        }
        else
        {
            if(ImageArray.length % 10 === 0)
            {
                params = {pageIndex:1+ImageArray.length/10};
            }
            else
            {
                jAlert('마지막 페이지 입니다.', '알림', 'c');
                return;
            }
        }

        $.mobile.loading("show");
        // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
        setTimeout(function()
                   {
                       fn_egov_sendto_server("/cmr/cameraPhotoAlbumListiOS.do",params);
                   }, 
                   500);
    }
}

/**
 * 사진 상세보기 이벤트
 * @returns 
 * @type 
 */
function fn_detailPhotoAlbum(VOsn) 
{
    if(fn_egov_network_check(false))        // 통신 이벤트 발생시 3G 사용자 승인여부 판단
    {
        currentImageSn = VOsn;
        var params = {
            sn : VOsn
        };

        $.mobile.loading("show");
        // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
        setTimeout(function()
                   {
                       fn_egov_sendto_server("/cmr/cameraPhotoAlbumDetailiOS.do",params);
                   }, 
                   500);
    }
}

/**
 * 사진 삭제 이벤트
 * @returns 
 * @type 
 */
function fn_deletePhotoAlbum() 
{
    if(fn_egov_network_check(false))        // 통신 이벤트 발생시 3G 사용자 승인여부 판단
    {
        jConfirm("삭제하시겠습니까?", "알림", "b", 
                 function(result)
                 {
                     if(result) 
                     {
                         var params = {
                             sn : currentImageSn
                         };

                         $.mobile.loading("show");
                         // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
                         setTimeout(function()
                                    {
                                        fn_egov_sendto_server("/cmr/deleteCameraPhotoAlbumiOS.do",params);
                                    }, 
                                    500);
                     }
                 });
    }
}


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
                                             if(serviceName === "/cmr/cameraPhotoAlbumListiOS.do")
                                             {  // 서버에 있는 사진 목록 리스트
                                                 $.mobile.changePage($("#listPhotoAlbum"));
                                                 fn_egov_add_imageList(result);
                                             }
                                             else if(serviceName === "/cmr/cameraPhotoAlbumCheckiOS.do")
                                             {   // 사진 제목 중복 체크
                                                 var cameraiOSAPIVO = result["cameraiOSAPIVO"];
                                                 var currentImageSn = cameraiOSAPIVO["sn"];
                                     
                                                 if(currentImageSn != null && currentImageSn != "") 
                                                 {
                                                     jConfirm("제목이 중복입니다.\n이미지를 수정하시겠습니까?", "알림", "b", 
                                                              function(result)
                                                              {
                                                                  if(result) 
                                                                  {
                                                                      fn_egov_update_Photograph(currentImageSn);
                                                                  }
                                                              });
                                                 }
                                                 else
                                                 {
                                                     jConfirm("저장하시겠습니까?", "알림", "b", 
                                                              function(result)
                                                              {
                                                                  if(result) 
                                                                  {
                                                                      fn_egov_insert_Photograph();
                                                                  }
                                                              });
                                                 }
                                             }
                                             else if(serviceName === "/cmr/htmlLoadiOS.do")
                                             {   // 서버 Url, 업로드 다운로드 Url
                                                 //context = result["serverContext"];
                                                 //downloadContext = result["downloadContext"];
                                             }
                                             else if(serviceName === "/cmr/cameraPhotoAlbumDetailiOS.do")
                                             {   // 리스트 목록 클릭후 상세조회
                                                 $.mobile.changePage($("#detailPhotoAlbum"));
                                                 var cameraiOSAPIVO = result["cameraiOSAPIVO"];
                                                 currentImageSn = cameraiOSAPIVO["fileSn"];
                                                 var photoSj = cameraiOSAPIVO["photoSj"];
                                                 var imageSrc = context + '/cmr/getImageiOS.do?fileSn=' + currentImageSn + '&uuid=' + encodeURIComponent(device.uuid);
                                                 $("#imageDetailSj").text("제목 : " + photoSj);
                                                 $("#imageDetailView").attr('src', imageSrc);
                                             }
                                             else if(serviceName === "/cmr/deleteCameraPhotoAlbumiOS.do")
                                             {   // 사진 정보 삭제
                                                 jAlert("삭제되었습니다", "알림", "b", 
                                                        function()
                                                        {
                                                            fn_egov_show_ImgList();
                                                        });
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

/**
 * 사진 서버로 전송 (새로 생성)
 * @returns 
 * @type 
 */
function fn_egov_insert_Photograph() 
{
    $.mobile.loading("show");
    // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
    setTimeout(function()
               {
                   var options = new FileUploadOptions();
                   options.fileKey = "file";
                   options.fileName = new Date().format("YYYYMMDDhhmmss") + ".jpg";
                   options.mimeType = "image/jpeg";
               
                   var params = {};
               
                   options.params = params;
                   var ft = new FileTransfer();
                   var serverPath = downloadContext + "/cmr/photoAlbumImageUploadiOS.do?uuid="+ encodeURI(device.uuid)+"&photoSj="+ encodeURIComponent($("#photoSj").val());
                   ft.upload(image, serverPath, fn_insertSuccess, fn_error, options);
               }, 
               500);
}

/**
 * 사진 서버로 전송 (기존 파일 변경)
 * @returns 
 * @type 
 */
function fn_egov_update_Photograph(currentImageSn) {
	
    $.mobile.loading("show");
    // 디바이스의 성능에 따라 PrograssDialog Show 가 완전이 로딩이 된후 다음 코드를 수행하도록 setTimeout 을 사용하여 지연시킨다.
    setTimeout(function()
               {
                   var options = new FileUploadOptions();
                   options.fileKey = "file";
                   options.fileName = new Date().format("YYYYMMDDhhmmss") + ".jpg";
                   options.mimeType = "image/jpeg";
               
                   var ft = new FileTransfer();
               
                   var params = {};
               
                   options.params = params;
                   var serverPath = downloadContext + "/cmr/photoAlbumImageUpdateiOS.do?sn="+currentImageSn;
                   ft.upload(image, serverPath, fn_insertSuccess, fn_error, options);
               }, 
               500);
}


/*********************************************************
 * Camera
 *********************************************************/

/**
 * 장치의 카메라 API 호출
 * @returns 
 * @type
 */
function fn_egov_capture_photo(sel)
{
    var cameraOption = {};
    if(sel == 'camera')
    {
        cameraOption  = {
            quality: 50,
            destinationType : Camera.DestinationType.FILE_URI,
            sourceType : Camera.PictureSourceType.CAMERA,
            targetWidth: 200,
            targetHeight: 200
        };
    }
    else
    {
        cameraOption  = {
            quality: 50,
            destinationType : Camera.DestinationType.FILE_URI,
            sourceType : Camera.PictureSourceType.PHOTOLIBRARY,
            targetWidth: 200,
            targetHeight: 200
        };
    }
    
    navigator.camera.getPicture(fn_egov_upload_photo,null,cameraOption);
};

/**
 * 사진을 찍은 뒤 use를 눌럿을 경우 호출됨
 * @returns 
 * @type imageURL
 */
function fn_egov_upload_photo(data)
{
    // this is where you would send the image file to server
    var html = "";
    image = data;

    html += '<img src="' + image + '" style="max-width: 100;"> </img>';

    $("#imageView").html(html);

    fn_egov_wait_iscroll('wrapper_image');
    
    // Successful upload to the server
    toast("uploadPhoto success!");
};



/*********************************************************
 * 공통
 *********************************************************/

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
function zeroPad(number) 
{
    return ( ( number < 10 ) ? "0" : "" ) + String(number);	
}

/**
 * iscroll 이 로딩 되기전 모든 컨트롤이 다 로딩 되도록 기달려 주는 함수
 * @returns
 * @type
 */
function fn_egov_wait_iscroll(thisPage)
{
    setTimeout(function()
    {
        if(myScroll != null) 
        {
            myScroll.destroy();
            ImageArray = null;
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

/**
 * 안드로이드의 toast 형태의 메시지 구현
 * @returns 현재시간
 * @type 
 */ 
function toast(sMessage) {
    if($(".toast").length <= 0)
    {
        var container = $(document.createElement("div"));
        container.addClass("toast");
        container.appendTo(document.body);
    }
    
    var message = $(document.createElement("div"));
    message.addClass("message");
    message.text(sMessage);
    message.appendTo($('.toast'));
    message.delay(100).fadeIn("slow", 
                              function() 
                              {
                                  $(this).delay(1500).fadeOut("slow", 
                                                              function()
                                                              {
                                                                  $(this).remove();
                                                              });
                              });
}
