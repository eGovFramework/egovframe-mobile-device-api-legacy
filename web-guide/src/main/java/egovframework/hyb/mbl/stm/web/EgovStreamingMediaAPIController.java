package egovframework.hyb.mbl.stm.web;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.AbstractView;

import egovframework.hyb.ios.dvc.service.DeviceiOSAPIVO;
import egovframework.com.cmm.security.DeviceAPIAuthSupport;
import egovframework.hyb.mbl.stm.service.EgovStreamingMediaAPIService;
import egovframework.hyb.mbl.stm.service.StreamingMediaAPIDefaultVO;
import egovframework.hyb.mbl.stm.service.StreamingMediaAPIFileVO;
import egovframework.hyb.mbl.stm.service.StreamingMediaAPIVO;
import egovframework.rte.fdl.property.EgovPropertyService;
/**  
 * @Class Name : EgovStreamingMediaAPIController.java
 * @Description : EgovStreamingMediaAPIController Class
 * @Modification Information  
 * @
 * @ 수정일               수정자              수정내용
 * @ ----------   ---------   -------------------------------
 *   2016.07.14   장성호              최초생성
 *   2020.09.16   신용호              Swagger 적용
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2016. 7. 14.
 * @version 1.0
 * @see
 * 
 */
@Controller
public class EgovStreamingMediaAPIController {

	/** EgovStreamingMediaAPIService */
	@Autowired
	private EgovStreamingMediaAPIService egovStreamingMediaAPIService;

	/** propertiesService */
	@Autowired
	protected EgovPropertyService propertiesService;

	@Autowired
	ServletContext servletContext;
	
	
	/**
	 * 미디어 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 StreamingMediaAPIVO
	 * @return 조회 목록
	 * @exception Exception
	 */
    	@RequestMapping("/stm/mediaInfoList.do")
	public @ResponseBody
	ModelAndView selectMediaInfoList(StreamingMediaAPIDefaultVO vo) throws Exception {
		
		ModelAndView jsonView = new ModelAndView("jsonView");
		
		List<?> streamingMediaAPIVO = egovStreamingMediaAPIService.selectMediaInfoList(vo);
		
		jsonView.addObject("resultSet", streamingMediaAPIVO);
		jsonView.addObject("resultState","OK");
		
		return jsonView;
	}

    @RequestMapping("/stm/updateMediaInfoRevivCo.do")
	public ModelAndView updateMediaInfoRevivCo(@RequestParam("sn") String sn, HttpServletRequest request) throws Exception {

		if (sn != null && !"".equals(sn)) {
			StreamingMediaAPIVO vo = new StreamingMediaAPIVO();
			vo.setSn(sn);
			vo.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, request.getParameter("uuid")));
			egovStreamingMediaAPIService.updateMediaInfoRevivCo(vo);
		}
		
		ModelAndView jsonView = new ModelAndView("jsonView");
		
		jsonView.addObject("resultState","OK");
		
		return jsonView;
	}

    @RequestMapping("/stm/getMediaStreaming.do")
	public ModelAndView getMediaStreaming(@RequestParam("sn") final String sn,
			final HttpServletRequest request, HttpServletResponse response) throws Exception {

		View streamView = new AbstractView() {
	        @Override
	        protected void renderMergedOutputModel(Map model, HttpServletRequest req, HttpServletResponse resp) throws Exception {
	            
	        	StreamingMediaAPIFileVO resultVO = null;
	    		if (sn != null && !"".equals(sn)) {
	    			StreamingMediaAPIFileVO vo = new StreamingMediaAPIFileVO();
	    			vo.setSn(Integer.parseInt(sn));
	    			vo.setUuid(DeviceAPIAuthSupport.resolveDeviceUuid(request, req.getParameter("uuid")));
	    			resultVO = egovStreamingMediaAPIService.selectMediaFileURL(vo);
	    		}
	    		if (resultVO == null) {
	    			resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Media access denied.");
	    			return;
	    		}

	    		RandomAccessFile rf = new RandomAccessFile(new File(
	    				resultVO.getFileStreCours().toString() + resultVO.getStreFileNm().toString()), "r");
	    		
	    		long rangeStart = 0;
	    		long rangeEnd = 0;
	    		boolean isPart = false;
	    		
	    		try{
	    			long movieSize = rf.length();
	    				String range = req.getHeader("range");
	    		
	    			if(range != null){
	    				if(range.endsWith("-")){
	    					range = range + (movieSize -1);
	    				}
	    				
	    				int idxm = range.trim().indexOf("-");
	    				rangeStart = Long.parseLong(range.substring(6,idxm));
	    				rangeEnd = Long.parseLong(range.substring(idxm +1));
	    				if(rangeStart > 0){
	    					isPart = true;
	    				}
	    			}else{
	    				rangeStart = 0;
	    				rangeEnd = movieSize -1;
	    			}
	    			
	    			long partSize = rangeEnd - rangeStart +1;
	    			
	    			resp.reset();	    			
	    			resp.setStatus(isPart ? 206 : 200);	
	    			resp.setContentType("video/"+ resultVO.getFileExtsn());
	    			resp.setHeader("Content-Disposition:", "attachment; filename=" + new String(resultVO.getOrignlFileNm().getBytes(), "UTF-8"));
	    			resp.setHeader("Content-Transfer-Encoding", "binary");
	    			resp.setHeader("Content-Range", "bytes"+rangeStart+"-"+rangeEnd+"/"+movieSize);
	    			resp.setHeader("Accept-Range", "bytes");
	    			resp.setHeader("Content-Length", ""+partSize);
	    			
	    			OutputStream out = resp.getOutputStream();
	    			rf.seek(rangeStart);
	    			
	    			int bufferSize = 8*1024;
	    			byte[] buf = new byte[bufferSize];
	    			do{
	    				int block = partSize > bufferSize ? bufferSize : (int)partSize;
	    				int len = rf.read(buf, 0, block);
	    				out.write(buf, 0, len);
	    				partSize -= block;
	    				
	    			}while(partSize > 0);
	    			
	    		}catch(IOException e){
	    			e.getStackTrace();
	    		}finally{
	    			rf.close();
	    		}
	    		
	        }
	    };
	    
	    return new ModelAndView(streamView);	    
		
	}
	
	
}
