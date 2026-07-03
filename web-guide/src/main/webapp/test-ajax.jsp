<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<html xmlns="http://www.w3.org/1999/xhtml" lang="ko">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<script  src="http://code.jquery.com/jquery-latest.min.js"></script>
    <script type="text/javaScript">
    
    var objErr;
    var objData;
    function callAjax() {

    	var serverUrl = $("#serverUrl").val();
    	alert("START CALL! => "+serverUrl);
		$.ajax({
		    url: serverUrl, //request 보낼 서버의 경로
		    type:'get', // 메소드(get, post, put 등)
		    data:{'id':'admin'}, //보낼 데이터
		    success: function(data) {
		        //서버로부터 정상적으로 응답이 왔을 때 실행
		        objData = data;
		        alert("Success data="+data);
		    },
		    error: function(err) {
		        //서버로부터 응답이 정상적으로 처리되지 못햇을 때 실행
		        objErr = err;
		    	alert("error="+err);
		    }
		});
    }
    
    $(document).ready(function() {
		$('#callAjaxBtn').click(function() { callAjax(); });
	});
	</script>
</head>

<body onload="">
<h1>AJAX Service Test</h1>
<br/><br/>

URL : <input type="text" id="serverUrl" value="./acl/xml/acceleratorInfoList.do" style="width:300px;"><br/><br/><br/>

<input type="button" id="callAjaxBtn" value="Call Ajax">

</body>

</html>
