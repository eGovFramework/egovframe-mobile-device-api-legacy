package egovframework.com.cmm.security;

import java.io.Serializable;

public class DeviceAPILoginVO implements Serializable {

    private static final long serialVersionUID = 1L;

    private int sn;
    private String userId;
    private String uuid;

    public int getSn() {
        return sn;
    }

    public void setSn(int sn) {
        this.sn = sn;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
}
