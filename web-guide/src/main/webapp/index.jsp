<%@ page contentType="text/html; charset=UTF-8" trimDirectiveWhitespaces="true"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>DeviceAPI Web 안내페이지</title>
<script type="text/javascript" src="js/jquery-1.11.0.min.js"></script>
<script type="text/javascript" src="js/sockjs-1.3.0.min.js"></script>
<!-- <script  src="http://code.jquery.com/jquery-latest.min.js"></script> -->
<script type="text/javaScript">
    
    var objErr;
    var objData;
    function callAjax() {
    	alert("START CALL!");
		$.ajax({
		    url:'/acl/xml/acceleratorInfoList.do', //request 보낼 서버의 경로
		    type:'get', // 메소드(get, post, put 등)
		    data:{'id':'admin'}, //보낼 데이터
		    success: function(data) {
		        //서버로부터 정상적으로 응답이 왔을 때 실행
		        objData = data;
		        alert("정상수신 , data = "+data);
		    },
		    error: function(err) {
		        //서버로부터 응답이 정상적으로 처리되지 못햇을 때 실행
		        objErr = err;
		    	alert("오류발생 , error="+err.state());
		    }
		});
		return false;
    }
</script>
<style>
#chatArea {
	width: 200px; height: 100px; overflow-y: auto; border: 1px solid black;
}
</style>
</head>
<body>
	<h1>DeviceAPI Web Service</h1>
	<h3>본 서비스는 전자정부 표준프레임워크 DeviceAPI App(하이브리드앱)과의 데이타 송수신 기능을 수행합니다.</h3>
	<h3>This service performs data transmission / reception with eGovFrame DeviceAPI Apps(Hybrid Mobile Apps).</h3>
	<hr width="100%" color="black">
	<br/><br/>
	<a href="./chat-sockjs.jsp">1. 웹소켓 테스트 화면 이동 (Move websocket test screen)</a><br/>
	<br/>
	<a href="./test-ajax.jsp">2. Ajax 데이타 송수신 테스트 (Ajax data transmission and reception test)</a><br/>
</body>
</html>