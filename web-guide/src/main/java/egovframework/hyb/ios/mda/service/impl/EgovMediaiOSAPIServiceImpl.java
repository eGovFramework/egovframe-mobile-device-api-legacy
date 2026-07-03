/*
 * Copyright 2008-2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package egovframework.hyb.ios.mda.service.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import egovframework.hyb.ios.mda.service.EgovMediaiOSAPIService;
import egovframework.hyb.ios.mda.service.MediaiOSAPIFileVO;
import egovframework.hyb.ios.mda.service.MediaiOSAPIVO;

import egovframework.rte.fdl.cmmn.EgovAbstractServiceImpl;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import javax.sound.sampled.AudioInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**  
 * @Class Name : EgovMediaiOSAPIServiceImpl.java
 * @Description : EgovMediaiOSAPIServiceImpl Class
 * @Modification Information  
 * @
 * @  수정일			수정자		수정내용
 * @ ---------		---------	-------------------------------
 * @ 2012. 7. 30.	이율경	   	최초생성
 * @ 2012. 8. 14.	이해성        커스터마이징
 * @ 2017.02. 27.   최두영        시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754]
 * 
 * @author 디바이스 API 실행환경 팀
 * @since 2012. 7. 30.
 * @version 1.0
 * @see
 * 
 */
@Service("EgovMediaiOSAPIService")
public class EgovMediaiOSAPIServiceImpl extends EgovAbstractServiceImpl implements
		EgovMediaiOSAPIService {

	/** CameraiOSAPIDAO */
	@Resource(name="MediaiOSAPIDAO")
    private MediaiOSAPIDAO mediaAPIDAO;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(EgovMediaiOSAPIServiceImpl.class);
	
	/**
	 * 녹음 Media를 등록한다.
	 * @param vo - 등록할 정보가 담긴 MediaiOSAPIVO
	 * @return void형
	 * @exception Exception
	 */
	public int insertMediaInfo(MediaiOSAPIVO vo, int fileSn) throws Exception {
		
		MediaiOSAPIFileVO fileVO = new MediaiOSAPIFileVO();
		fileVO.setUuid(vo.getUuid());
		fileVO.setFileSn(fileSn);
		fileVO.setMdCode("MLT03");
		fileVO.setMdSj(vo.getMdSj());
		fileVO.setUseyn("Y");
		fileVO.setRevivCo("0");
		
		return mediaAPIDAO.insertMediaInfo(fileVO);
	}
	
	/**
	 * 녹음 파일을 등록한다.
	 * @param vo - 등록할 정보가 담긴 MediaiOSAPIFileVO
	 * @return void형
	 * @exception Exception
	 */
	public int insertMediaRecordFile(MediaiOSAPIFileVO vo) throws Exception {
		return mediaAPIDAO.insertMediaRecordFile(vo);
	}
	
	/**
	 * 미디어 정보를 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIVO
	 * @return 조회 목록
	 * @exception Exception
	 */
		
	public MediaiOSAPIFileVO selectMediaInfoDetail(MediaiOSAPIVO vo) throws Exception {
		mediaAPIDAO.updateMediaInfoRevivCo(vo);
		return mediaAPIDAO.selectMediaInfoDetail(vo);
	}
	
	/**
	 * 미디어 목록을 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIDefaultVO
	 * @return 조회 목록
	 * @exception Exception
	 */
	public List<?> selectMediaInfoList(MediaiOSAPIVO vo) throws Exception {
		
		return mediaAPIDAO.selectMediaInfoList(vo);
	}
	
	
	/**
	 * 미디어 파일을 조회한다.
	 * @param VO - 조회할 정보가 담긴 MediaiOSAPIFileVO
	 * @return 파일 정보
	 * @exception Exception
	 */
	public boolean selectMediaFileInf(HttpServletResponse response, MediaiOSAPIFileVO vo) throws Exception {
		File file = null;
		FileInputStream fis = null;
	
		BufferedInputStream in = null;
		ByteArrayOutputStream bStream = null;
		MediaiOSAPIFileVO fileVO = mediaAPIDAO.selectMediaFileInfo(vo);
		if (fileVO == null) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "File access denied.");
			return false;
		}

		String type = "";
		boolean errorFlag = true;
		try {
			//file = new File("/Users/eGovframe/Downloads/FileDownload/" + "owlband.mp3");
		    file = new File(fileVO.getFileStreCours(), fileVO.getStreFileNm());
		    
		    fis = new FileInputStream(file);
	
		    /*
		    // ========== SoundFile Information ===========
		    AudioInputStream audioInputStream = AudioSystem.getAudioInputStream(fis);
			System.out.println("AudioInputStream length = " + audioInputStream.getFrameLength() + " sample frames.");
			//getting an AudioFormat from an AudioInputStream
			AudioFormat audioFormat = audioInputStream.getFormat();
			System.out.println("Audio format = " + audioFormat.toString());
			//for PCM encoding, frame size is simply: channels * sampleSizeInBits / 8;
			System.out.println("Frame size = " + audioFormat.getFrameSize() + " bytes.");
			double dduration = audioInputStream.getFrameLength() / audioFormat.getFrameRate();
			System.out.println("Duration = " + dduration + " seconds.");
			int naudioData[] = getAudioData(audioInputStream);
			System.out.println("Signal average power = " + calculatePower(naudioData) + " (Watts, assuming data in Volts over resistance = 1 Ohm)");
			System.out.println("Signal minimum value = " + calculateMinimum(naudioData) + " (Volts)");
			System.out.println("Signal maximum value = " + calculateMaximum(naudioData) + " (Volts)");    
			*/
		    
		    // ========== Sound file banary ===========
		    in = new BufferedInputStream(fis);
		    bStream = new ByteArrayOutputStream();
	
		    int imgByte;
		    while ((imgByte = in.read()) != -1) {
		    	bStream.write(imgByte);
		    }
		    
			if (fileVO.getMdCode() != null && !"".equals(fileVO.getMdCode()) && 
					fileVO.getFileExtsn() != null && !"".equals(fileVO.getFileExtsn())) {
				
				type = "audio/" + fileVO.getFileExtsn();
		
			} else {
				LOGGER.debug("Media fileType is null.");
			}
		   
			response.setHeader("Content-Type", type);
		    response.setHeader("Content-Disposition", "attachment;filename='"+fileVO.getStreFileNm()+"'");
		    
			response.setContentLength(bStream.size());
			bStream.writeTo(response.getOutputStream());
		
			response.getOutputStream().flush();
			response.getOutputStream().close();

		    
		    /*
		    // ========== Wav file streaming ===========
		    // Set to expire far in the past.
		    response.setDateHeader("Expires", 0);
		    // Set standard HTTP/1.1 no-cache headers.
		    response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
		    // Set IE extended HTTP/1.1 no-cache headers (use addHeader).
		    response.addHeader("Cache-Control", "post-check=0, pre-check=0");
		    // Set standard HTTP/1.0 no-cache header.
		    response.setHeader("Pragma", "no-cache");

		    // return a wav
		    response.setContentType("audio/wav");

		    AudioInputStream audioInputStream = AudioSystem.getAudioInputStream(fis);
		    ServletOutputStream out = response.getOutputStream();

		    // write the data out   	
		    ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		    AudioSystem.write(audioInputStream,javax.sound.sampled.AudioFileFormat.Type.WAVE,byteOutputStream);
		    out.write(byteOutputStream.toByteArray());
		    */
		//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 207-207
		}catch(NullPointerException e){
			LOGGER.error("[IOException] Try/Catch...IOException : " + e.getMessage());
			errorFlag = false;
		}catch(Exception e) {
			LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
			errorFlag = false;
		} finally {
			if (bStream != null) {
				try {
					bStream.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 214-214
				}catch(IOException e){
					LOGGER.error("[IOException] Try/Catch...IOException : " + e.getMessage());
					errorFlag = false;
				} catch (Exception e) {
					LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
					errorFlag = false;
				}
			}
			if (in != null) {
				try {
					in.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 222-222
				}catch(IOException e){
					LOGGER.error("[IOException] Try/Catch...IOException : " + e.getMessage());
					errorFlag = false;
				} catch (Exception e) {
					LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
					errorFlag = false;
				}
			}
			if (fis != null) {
				try {
					fis.close();
				//2017-02-27 최두영 시큐어코딩(ES)-36. 부적절한 예외 처리[CWE253, CWE-440, CWE-754] 230-230
				}catch(IOException e){
					LOGGER.error("[IOException] Try/Catch...IOException : " + e.getMessage());
					errorFlag = false;
				} catch (Exception e) {
					LOGGER.error("["+e.getClass()+"] Try/Catch... : " + e.getMessage());
					errorFlag = false;
				}
			}
		}
		
		return errorFlag;
	}
	
	public static int[] getAudioData(AudioInputStream audioInputStream)
	{				
		int nlengthInFrames = (int) audioInputStream.getFrameLength();
        int nframeSizeInBytes = audioInputStream.getFormat().getFrameSize();
		
		int nlengthInBytes = nlengthInFrames * nframeSizeInBytes;
		//System.out.println("File has " + nlengthInBytes + " bytes of audio data.");
		
		byte[] audioBytes = new byte[nlengthInBytes];
		try {
			audioInputStream.read(audioBytes);
		} catch (IOException e) {
			LOGGER.debug("IOException - Method : getAudioData() {}", e.getMessage());
		}		
				
		int nlengthInSamples;
		int[] naudioSamples = null;
		
		if (audioInputStream.getFormat().getSampleSizeInBits() == 16) {
			nlengthInSamples = nlengthInBytes / 2;
			naudioSamples = new int[nlengthInSamples];
			
			if (audioInputStream.getFormat().isBigEndian()) {
				for (int i=0; i<nlengthInSamples; i++) {
					int MSB = (int) audioBytes[2*i]; //First byte is MSB (high order).
					int LSB = (int) audioBytes[2*i+1]; //Second byte is LSB (low order).					
					naudioSamples[i] = MSB<<8 | (255 & LSB); //int int_val = 256*MSB | (255 & LSB);
				}
			} else { //little-endian
				for (int i=0; i<nlengthInSamples; i++) {
					int LSB = (int) audioBytes[2*i]; //First byte is LSB (low order).
					int MSB = (int) audioBytes[2*i+1]; //Second byte is MSB (high order).					
					naudioSamples[i] = MSB<<8 | (255 & LSB); //int int_val = 256*MSB | (255 & LSB);
				}
			}							

		} else if (audioInputStream.getFormat().getSampleSizeInBits() == 8) {
			nlengthInSamples = nlengthInBytes;
			naudioSamples = new int[nlengthInSamples];
			if (audioInputStream.getFormat().getEncoding().toString().startsWith("PCM SIGNED")) {
				for (int i=0; i<nlengthInBytes; i++) {
					naudioSamples[i] = audioBytes[i];
				}
			} else { //unsigned
				for (int i=0; i<nlengthInBytes; i++) {
					naudioSamples[i] = audioBytes[i]-128;
				}
			}
			
		} else { //sample size is not 8 or 16 bits/sample
			return null;
		}
		
		return naudioSamples;
	}
	
	/** Calculates the average power, i.e., the expected value
	 * of data signal squared.
	 */
	public static double calculatePower(int[] naudioData)
	{
		double dpower = 0.0;
		
		for (int i=0; i<naudioData.length; i++) {
			dpower += naudioData[i] * naudioData[i];
		}
		
		dpower /= naudioData.length;
		
		return dpower;
	}

	
	/** Calculates the maximum value of data
	 */
	public static double calculateMaximum(int[] naudioData)
	{
		double dmaximum = -Double.MAX_VALUE;
		
		for (int i=0; i<naudioData.length; i++) {
			if (naudioData[i] > dmaximum) {
				dmaximum = naudioData[i];
			}
		}				
		return dmaximum;
	}
	

	/** Calculates the minimum value of data
	 */
	public static double calculateMinimum(int[] naudioData)
	{
		double dminimum = Double.MAX_VALUE;
		
		for (int i=0; i<naudioData.length; i++) {
			if (naudioData[i] < dminimum) {
				dminimum = naudioData[i];
			}
		}				
		return dminimum;
	}
}
