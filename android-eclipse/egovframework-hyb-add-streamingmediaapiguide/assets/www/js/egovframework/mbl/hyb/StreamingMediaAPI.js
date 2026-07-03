
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

/**
 * @fileoverview 모바일 전자정부 하이브리드 앱 스트리밍 미디어 API 가이드 프로그램 JavaScript
 * JavaScript.
 *
 * @author 장성호
 * @version 1.0
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2016. 7. 11.   장성호 		iscroll5 적용
 */

/*********************************************************
 * A TAG 링크 컨트롤
 *********************************************************/

var server_url;
/**
 * A tag의 링크 변경
 * @returns
 * @type
 */
function fn_egov_init_hrefLink(){
    // 리소스 업데이트 플러그인 테스트
    console.log(">> button fn Setted");
    $("#btnMediaList").attr("href","javascript:fn_egov_medialist();");
    
    plugins.EgovInterface.geturl(function getURLString(resURL){
    	server_url = resURL;
    });
}

var jsonresult;

function fn_egov_medialist() {
    
    console.log(">> media List");
    var url = "/stm/mediaInfoList.do";
    var params = {};
    fileSN ="";
    window.plugins.EgovInterface.request(url, params, function(jsondata) {
            resultJson = jsondata;
            if (resultJson.resultSet.length == 0) {
                jAlert('서버에 저장된 미디어\n 목록이 없습니다.','알림','b');
                return;
            }

            if(resultJson.resultState == "OK"){
               var strhtml="";
               $(resultJson.resultSet).each(function(){
                                            
                         var sn = this.sn;
                         var mdSj = fn_egov_escapeHtml(this.mdSj);
                         var revivCo = fn_egov_escapeHtml(this.revivCo);
                         var mdcode = fn_egov_escapeHtml(this.mdCode);
                                                                
                         strhtml += '<li>';
                         strhtml += '     <a href="#" onclick="javascript:fn_egov_filelist_go(\'' + sn + '\')">';
                         strhtml += '         <h3>제목:  ' + mdSj + '</h3>';
                         strhtml += '         <h3>파일타입: ' + mdcode + '</h3>';
                         strhtml += '         <h3>재생횟수:  ' +  revivCo + '</h3>';
                         strhtml += '    </a>';
                         strhtml += '</li>';
                                                                      
                    });
                                         
                var theList = $('#theList');
                theList.html(strhtml);
                $.mobile.changePage("#mediaInfo", "slide", false, false);
                theList.listview("refresh");
                infoScroll.refresh();
                                         
            }else{
                $("#alert_dialog").click( function() {
                      jAlert('데이터 전송 중 오류가 발생 했습니다.', '전송 오류', 'c');
                      });
                  }
                                         
            }, function(result){
                    alert("error > "+result);
            });
    
}


function fn_egov_filelist_go(input) {
  
    jConfirm('동영상을 재생하시겠습니까?', '알림', 'c', function(r) {
        if (r == true) {
        	var resultURL = server_url + "/stm/getMediaStreaming.do?sn=" + input + "&uuid=" + encodeURIComponent(device.uuid);                	
        	fn_egov_playMedia(resultURL, input);        
        }
    });
               
}

function fn_egov_playMedia(resultURL, input){
  
    var options = {
        successCallback: function() {
            console.log("Video was closed without error.");
            $.mobile.changePage("#main", "slide", false, false);
        },
        errorCallback: function(errMsg) {
            console.log("Error! " + errMsg);
        },
        orientation: '' // 'landscape'
    };
    
    fn_egov_updateMediaInfoRevivCo(input);
    window.plugins.streamingMedia.playVideo(resultURL, options);

}


function fn_egov_updateMediaInfoRevivCo(inputSn){
    var url = "/stm/updateMediaInfoRevivCo.do";
    var params = {sn : inputSn, uuid : device.uuid};
    console.log(">>> inputSn:" + inputSn);
    
    window.plugins.EgovInterface.request(url, params, function(jsondata) {
            resultJson = jsondata;
                                         
            if(resultJson.resultState == "OK"){
                console.log("RevivCo Update OK.");
            }else{
                console.log("RevivCo Update Error.");
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