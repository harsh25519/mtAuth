package bdj.hkb.auth_service.ratelimit;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    // 50KB limit is more than enough for a standard JSON auth payload
    private static final int MAX_PAYLOAD_SIZE = 50 * 1024;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);

        InputStream is = request.getInputStream();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int totalBytes = 0;
        int bytesRead;

        while ((bytesRead = is.read(data, 0, data.length)) != -1) {
            totalBytes += bytesRead;
            if (totalBytes > MAX_PAYLOAD_SIZE) {
                throw new IOException("Payload exceeds maximum size allowed for authentication endpoints.");
            }
            buffer.write(data, 0, bytesRead);
        }

        this.cachedBody = buffer.toByteArray();
    }

    @Override
    public ServletInputStream getInputStream() {
        return new CachedBodyServletInputStream(cachedBody);
    }

    private static class CachedBodyServletInputStream extends ServletInputStream {
        private final InputStream buffered;

        CachedBodyServletInputStream(byte[] body) {
            this.buffered = new ByteArrayInputStream(body);
        }

        @Override
        public int read() throws IOException {
            return buffered.read();
        }

        @Override
        public boolean isFinished() {
            try {
                return buffered.available() == 0;
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException("Async body reads not supported here");
        }
    }
}
