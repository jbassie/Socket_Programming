import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateExpiredException;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class Server {
    private static final Logger logger = Logger.getLogger(Server.class.getName());
    private static List<String> cachedContent = null;
    private static ExecutorService threadPool = Executors.newCachedThreadPool();
    private static boolean shutdownFlag = false;

    public static void main(String[] args) {
        startServer();
    }

    public static void startServer() {
        Properties config = readConfigFile("src/config.ini");
        boolean sslEnabled = Boolean.parseBoolean(config.getProperty("ENABLE_SSL"));
        String certFile = config.getProperty("CERTFILE");
        String keyFile = config.getProperty("KEYFILE");
        String filePath = config.getProperty("FILEPATH");
        boolean rereadOnQuery = Boolean.parseBoolean(config.getProperty("REREAD_ON_QUERY"));

        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            logger.info("Server started on port 8080");

            SSLContext sslContext = null;

            if (sslEnabled) {
                logger.info("SSL is enabled. Wrapping Socket");
                sslContext = createSSLContext(certFile, keyFile);
            }

            while (!shutdownFlag) {
                Socket clientSocket = serverSocket.accept();
                if (sslEnabled && sslContext != null) {
                    clientSocket = sslContext.getSocketFactory().createSocket(clientSocket, null, clientSocket.getPort(), true);
                }
                logger.info("Accepted connection from client " + clientSocket.getRemoteSocketAddress());
                threadPool.submit(new ClientHandler(clientSocket, filePath, rereadOnQuery));
            }
        } catch (IOException e) {
            logger.severe("Server error: " + e.getMessage());
        }
    }

    private static SSLContext createSSLContext(String certFile, String keyFile) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            char[] password = "changeit".toCharArray();
            try (InputStream keyFileStream = new FileInputStream(keyFile)) {
                keyStore.load(keyFileStream, password);
            }

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, password);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
            return sslContext;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateExpiredException | IOException | UnrecoverableKeyException | KeyManagementException e) {
            logger.severe("Failed to create SSL context: " + e.getMessage());
            return null;
        }
    }

    public static Properties readConfigFile(String filePath) {
        Properties properties = new Properties();
        try (FileInputStream fis = new FileInputStream(filePath)) {
            properties.load(fis);
        } catch (IOException e) {
            logger.severe("Error reading config file: " + e.getMessage());
        }
        return properties;
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private String filePath;
        private boolean rereadOnQuery;

        public ClientHandler(Socket clientSocket, String filePath, boolean rereadOnQuery) {
            this.clientSocket = clientSocket;
            this.filePath = filePath;
            this.rereadOnQuery = rereadOnQuery;
        }

        @Override
        public void run() {
            try (
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))
            ) {
                String buffer;
                while ((buffer = in.readLine()) != null) {
                    logger.info("Received query: " + buffer);
                    long startTime = System.currentTimeMillis();
                    String response = matchString(buffer, filePath, rereadOnQuery);
                    long executionTime = System.currentTimeMillis() - startTime;
                    logger.info("Execution time: " + executionTime + " ms");

                    out.write(response + "\n");
                    out.flush();
                }
            } catch (IOException e) {
                logger.severe("Error handling client: " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                    logger.info("Closed connection with client");
                } catch (IOException e) {
                    logger.severe("Error closing client socket: " + e.getMessage());
                }
            }
        }
    }

    public static String matchString(String searchString, String filePath, boolean reread) throws IOException {
        Pattern pattern = Pattern.compile(Pattern.quote(searchString) + "\\R");
        if (searchString.trim().isEmpty()) {
            return "STRING NOT FOUND";
        }

        try (RandomAccessFile raf = new RandomAccessFile(filePath, "r");
             FileChannel channel = raf.getChannel()) {
            if (reread || cachedContent == null) {
                logger.info("Re-reading file using memory-mapped IO");
                cachedContent = Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8);
            }

            for (String line : cachedContent) {
                if (pattern.matcher(line).find()) {
                    return "STRING EXISTS";
                }
            }
            return "STRING NOT FOUND";
        }
    }
}
