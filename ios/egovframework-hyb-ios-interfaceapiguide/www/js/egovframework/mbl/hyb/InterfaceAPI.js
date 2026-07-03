/** 
 * @fileoverview 모바일 전자정부 하이브리드 앱 Interface API 가이드 프로그램 JavaScript
 * JavaScript. 
 *
 * @author 나신일
 * @version 1.0 
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2015. 4. 20.   신용호 		iscroll5 적용 
 */

/** iscroll를 적용하기 위한 공통 */
var myScroll = null;

/*********************************************************
 * HTML 및 이벤트 관련 함수
 *********************************************************/

/**
 * 화면을 위한 관련 이벤트
 */

$(function(){
    $.validator.setDefaults({
        onkeyup:false,
        onclick:false,
        onfocusout:false,
        submitHandler: function() { 
            //3G 사용시 과금이 발생 할 수 있다는 경고 메시지 표시
            if(!fn_egov_network_check(false)) {
                return;
            }

            if($.mobile.activePage.is('#login')) {
                // 로그인
                fn_egov_login_member();         				 
            } else if($.mobile.activePage.is('#signUp')) {
                // 회원가입
                fn_egov_subscribe_member();
            } else  if($.mobile.activePage.is('#secessionMember')) {
                // 회원탈퇴
                $("#secessionMemberBtn").focus();
                fn_egov_confirm_secession(); 
            }
        }
    });

    // validation check
    $("#subscribeForm").validate();
    $("#loginForm").validate();
    $("#secessionForm").validate();

    $('#loginMoveBtn').click(function () {
        // 로그인 화면 이동
        fn_egov_go_login();
    });
    
    $(document).on("pageshow", "#importanceList", function(event, ui){
        
        if(myScroll != null) {
            
            myScroll.destroy();
        }
        loaded('#wrapperInfo');
    });
});

/**
 * PhoneGap 초기화 이벤트에서 호출하는 function
 * @returns iscroll 과 Back 버튼 event 추가
 * @type
*/
function DeviceAPIInit() {
    loaded('#wrapperInfo');
  	
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
 * 회원가입 화면 이동 function.
 * @returns 화원가입 화면으로 이동.
 * @type
*/
function fn_egov_go_signUp() {
    $('#subscribeForm').each(function(){
        this.reset();
    });

    $.mobile.changePage("#signUp", "slide", false, false);
}

/**
 * 로그인 화면 이동 function.
 * @returns 로그인 화면으로 이동.
 * @type
*/
function fn_egov_go_login() {
    $('#loginForm').each(function(){
        this.reset();
    });

    $.mobile.changePage("#login", "slide", false, false);
}

/**
 * 회원탈퇴 화면 이동 function.
 * @returns 화원탈퇴 화면으로 이동.
 * @type
*/
function fn_egov_go_secession() {
    $('#secessionForm').each(function(){
        this.reset();
    });

    $.mobile.changePage("#secessionMember", "slide", false, false);
}

/**
 * login 정보 서버 전송 function.
 * @returns 로그인 성공 여부
 * @type  
*/
function fn_egov_login_member() {
    var url = "/itf/xml/logIn.do";
    var acceptType = "xml";
    var userid = $("#loginId").val();
    var userpw = $("#loginPasswd").val();

    $.mobile.loading("show");

    var params = {uuid :  device.uuid,
            userId: userid,
            userPw: userpw};

        alert('전송방식:RESTful\n전송타입:POST('+ acceptType + ')\nparam:' + JSON.stringify(params).replace(userpw,'****'));

    // get the data from server
    window.plugins.EgovInterface.post(url, acceptType, params, function(xmldata) {		
    /*
    var data = JSON.parse(jsondata);		
    if(data.resultState == "OK"){
        $.mobile.changePage("#secessionMember", "slide", false, false);
    }else{
        jAlert(data.resultMessage, '오류', 'c');
    }*/
        console.log('DeviceAPIGuide fn_egov_login_member request Complete');
        alert('응답방식:RESTful\n응답타입:POST('+ acceptType + ')\nparam:' + xmldata.replace(userpw,'****'));		
        $.mobile.loading("hide");
        if($(xmldata).find("resultState").text() == "OK"){
                window.history.back();
            }else{
                jAlert($(xmldata).find("resultMessage").text(), '오류', 'c');
            }

        });	


}

/**
 * 회원가입 정보 서버 전송 function.
 * @returns 회원가입 성공 여부
 * @type  
*/

function fn_egov_subscribe_member() {	
    var url = "/itf/xml/addInterfaceInfo.do";
    var acceptType = "xml";
    var userid = $("#signUpId").val();
    var userpw = $("#signUpPasswd").val();
    var emails = $("#signUpEmail").val();	
    
    var params = {uuid :  device.uuid,			 
            userId: userid,
            userPw: userpw,
            emails: emails};
    $.mobile.loading("show");
    alert('전송방식:RESTful\n전송타입:POST('+ acceptType + ')\nparam:' + JSON.stringify(params).replace(userpw,'****'));
    
    // get the data from server
    window.plugins.EgovInterface.post(url, acceptType, params, function(xmldata) {
        /*
        var data = JSON.parse(jsondata);		
        if(data.resultState == "OK"){
            $.mobile.changePage("#login", "slide", false, false);
        }else{
            jAlert(data.resultMessage, '오류', 'c');
        }*/
        console.log('DeviceAPIGuide fn_egov_subscribe_member request Complete');
        alert('응답방식:RESTful\n응답타입:POST('+ acceptType + ')\nparam:' + xmldata);		
        $.mobile.loading("hide");
        if($(xmldata).find("resultState").text() == "OK"){
            
            window.history.back();
        }else{
            jAlert($(xmldata).find("resultMessage").text(), '오류', 'c');
        }
    });


}


/**
 * 회원탈퇴 정보 서버 전송 function.
 * @returns 회원 탈퇴 성공 여부
 * @type  
*/
function fn_egov_secession_member() {
    var url = "/itf/xml/withdrawal.do";
    var acceptType = "xml";
    var userid = $("#secessionMemberId").val();
    var userpw = $("#secessionMemberPasswd").val();
    

    var params = {uuid :  device.uuid,
            userId: userid,
            userPw: userpw};
    $.mobile.loading("show");
    alert('전송방식:RESTful\n전송타입:POST('+ acceptType + ')\nparam:' + JSON.stringify(params).replace(userpw,'****'));
    
    // get the data from server
    window.plugins.EgovInterface.post(url, acceptType, params, function(xmldata) {
        /*
        var data = JSON.parse(jsondata);
        if(data.resultState == "OK"){
            jAlert(data.resultMessage, '성공', 'c', function(r){
                if(r == true){
                    $.mobile.changePage("#signUp", { transition: "slide", reverse: true });
        }else{
        }
        });
        }else{
        jAlert(data.resultMessage, '오류', 'c');
        }		
         */
        console.log('DeviceAPIGuide fn_egov_secession_member request Complete');
        alert('응답방식:RESTful\n응답타입:POST('+ acceptType + ')\nparam:' + xmldata);
        $.mobile.loading("hide");
        if($(xmldata).find("resultState").text() == "OK"){
            jAlert($(xmldata).find("resultMessage").text(), '성공', 'c', function(r){
                if(r == true){
                    window.history.back();
                }
            });
        }else{
            jAlert($(xmldata).find("resultMessage").text(), '오류', 'c');
        }
    });
}

/**
 * 회원 탈퇴 확인 function.
 * @returns 회원 탈퇴 전 사용자 확인을 수행한다.
 * @type  
*/
function fn_egov_confirm_secession(){
    jConfirm('회원탈퇴 하시겠습니까??', '알림', 'c', function(r){
        if(r == true){
            fn_egov_secession_member();
        }
    });	
}

