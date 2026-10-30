package btxds.dekal.transmitter;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

public class FileServer {

    private static HttpServer server;
    private static final Gson GSON = new Gson();

    private record CachedHash(String hash, long lastModified, long size) {}
    private static final Map<Path, CachedHash> HASH_CACHE = new ConcurrentHashMap<>();

    public static synchronized void start() {
        if (server != null) return;

        try {
            AccountManager.init();

            if (!Files.exists(Config.SERVER_FILEHOST_DIR)) {
                Files.createDirectories(Config.SERVER_FILEHOST_DIR);
            }

            // Создаем папку game, если ее еще нет
            Path gameDir = Config.SERVER_FILEHOST_DIR.resolve("game");
            if (!Files.exists(gameDir)) {
                Files.createDirectories(gameDir);
            }

            server = HttpServer.create(new InetSocketAddress(Config.SERVER_FILEHOST_PORT), 0);
            server.createContext("/", FileServer::handleRequest);

            server.setExecutor(Executors.newFixedThreadPool(4));
            server.start();

            Main.LOGGER.info("[Dekal Transmitter] Web-Server launched at port {}", Config.SERVER_FILEHOST_PORT);
        } catch (IOException e) {
            Main.LOGGER.error("[Dekal Transmitter] Launch error: ", e);
        }
    }

    public static synchronized void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
            HASH_CACHE.clear();
        }
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        if (path.startsWith("/")) {
            path = path.substring(1);
        }

        try {
            if ("POST".equalsIgnoreCase(method)) {
                handlePostRequests(exchange, path);
                return;
            }

            if ("GET".equalsIgnoreCase(method)) {
                handleGetRequests(exchange, path);
                return;
            }

            exchange.sendResponseHeaders(405, -1);
            exchange.close();

        } catch (Exception e) {
            sendError(exchange, 500, "Internal Server Error");
        } finally {
            exchange.close();
        }
    }

    private static void handlePostRequests(HttpExchange exchange, String path) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

        switch (path.toLowerCase()) {
            case "auth/register" -> {
                JsonObject json = GSON.fromJson(body, JsonObject.class);
                String user = json.has("username") ? json.get("username").getAsString() : "";
                String pass = json.has("password") ? json.get("password").getAsString() : "";
                String hwid = json.has("hwid") ? json.get("hwid").getAsString() : null;

                AccountManager.AuthResponse resp = AccountManager.register(user, pass, hwid);
                sendJsonResponse(exchange, resp.success() ? 200 : 400, GSON.toJson(resp));
            }
            case "auth/login" -> {
                JsonObject json = GSON.fromJson(body, JsonObject.class);
                String user = json.has("username") ? json.get("username").getAsString() : "";
                String pass = json.has("password") ? json.get("password").getAsString() : "";
                String hwid = json.has("hwid") ? json.get("hwid").getAsString() : null;

                AccountManager.AuthResponse resp = AccountManager.login(user, pass, hwid);
                sendJsonResponse(exchange, resp.success() ? 200 : 401, GSON.toJson(resp));
            }
            case "auth/verify" -> {
                JsonObject json = GSON.fromJson(body, JsonObject.class);
                String token = json.has("token") ? json.get("token").getAsString() : "";
                String hwid = json.has("hwid") ? json.get("hwid").getAsString() : null;

                AccountManager.AuthResponse resp = AccountManager.verifySession(token, hwid);
                sendJsonResponse(exchange, resp.success() ? 200 : 401, GSON.toJson(resp));
            }
            case "auth/join", "session/minecraft/join" -> {
                JsonObject json = GSON.fromJson(body, JsonObject.class);
                String token = json.has("accessToken") ? json.get("accessToken").getAsString() : "";
                String profile = json.has("selectedProfile") ? json.get("selectedProfile").getAsString() : "";
                String serverId = json.has("serverId") ? json.get("serverId").getAsString() : "";

                boolean ok = AccountManager.processClientJoin(token, profile, serverId);
                if (ok) {
                    exchange.sendResponseHeaders(204, -1);
                } else {
                    sendError(exchange, 403, "Invalid session token");
                }
            }
            default -> sendError(exchange, 404, "Not Found");
        }
    }

    private static void handleGetRequests(HttpExchange exchange, String path) throws IOException {
        if ("auth/hasjoined".equalsIgnoreCase(path) || "session/minecraft/hasjoined".equalsIgnoreCase(path)) {
            Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());
            String username = params.get("username");
            String serverId = params.get("serverId");

            if (username == null || serverId == null) {
                sendError(exchange, 400, "Missing parameters");
                return;
            }

            AccountManager.PendingJoin join = AccountManager.processServerHasJoined(username, serverId);
            if (join == null) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            JsonObject response = new JsonObject();
            response.addProperty("id", join.uuid());
            response.addProperty("name", join.username());
            response.add("properties", GSON.toJsonTree(new Object[0]));

            sendJsonResponse(exchange, 200, GSON.toJson(response));
            return;
        }

        // Манифест модов (только файлы папки mods/*.jar)
        if ("mods/manifest".equalsIgnoreCase(path)) {
            Path modsDir = Config.SERVER_FILEHOST_DIR.resolve("mods");
            Map<String, String> modsMap = new HashMap<>();

            if (Files.exists(modsDir) && Files.isDirectory(modsDir)) {
                try (var stream = Files.list(modsDir)) {
                    stream.filter(p -> p.toString().endsWith(".jar")).forEach(p -> {
                        try {
                            modsMap.put(p.getFileName().toString(), getOrComputeHash(p));
                        } catch (Exception ignored) {}
                    });
                }
            }

            sendJsonResponse(exchange, 200, GSON.toJson(modsMap));
            return;
        }

        // Рекурсивный манифест игровых компонентов (launcher/game/**)
        if ("game/manifest".equalsIgnoreCase(path)) {
            Path gameDir = Config.SERVER_FILEHOST_DIR.resolve("game");
            Map<String, String> gameMap = new HashMap<>();

            if (Files.exists(gameDir) && Files.isDirectory(gameDir)) {
                try (Stream<Path> stream = Files.walk(gameDir)) {
                    stream.filter(Files::isRegularFile).forEach(p -> {
                        try {
                            // Относительный путь в формате "config/example.toml"
                            String relative = gameDir.relativize(p).toString().replace('\\', '/');
                            gameMap.put(relative, getOrComputeHash(p));
                        } catch (Exception ignored) {}
                    });
                }
            }

            sendJsonResponse(exchange, 200, GSON.toJson(gameMap));
            return;
        }

        // Проверка наличия суффикса /hash для любого файла
        boolean isHashRequest = path.endsWith("/hash");
        if (isHashRequest) {
            path = path.substring(0, path.length() - 5);
        }

        Path targetFile = Config.SERVER_FILEHOST_DIR.resolve(path).normalize();

        // Защита от выхода за пределы папки launcher (Path Traversal)
        if (!targetFile.startsWith(Config.SERVER_FILEHOST_DIR) || Files.isDirectory(targetFile) || !Files.exists(targetFile)) {
            sendError(exchange, 404, "File Not Found");
            return;
        }

        // Отдача хеша SHA-256
        if (isHashRequest) {
            try {
                String sha256 = getOrComputeHash(targetFile);
                byte[] responseBytes = sha256.getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(200, responseBytes.length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
                return;
            } catch (Exception e) {
                sendError(exchange, 500, "Hash computation error");
                return;
            }
        }

        // Отдача самого файла
        long fileSize = Files.size(targetFile);
        String contentType = getContentType(targetFile.getFileName().toString());

        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, fileSize);

        try (InputStream in = Files.newInputStream(targetFile);
             OutputStream out = exchange.getResponseBody()) {
            byte[] buffer = new byte[65536];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.flush();
        }
    }

    private static Map<String, String> parseQueryParams(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.isBlank()) return map;
        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            if (pair.length == 2) {
                map.put(pair[0], pair[1]);
            }
        }
        return map;
    }

    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String getOrComputeHash(Path file) throws Exception {
        long lastModified = Files.getLastModifiedTime(file).toMillis();
        long size = Files.size(file);

        CachedHash cached = HASH_CACHE.get(file);
        if (cached != null && cached.lastModified() == lastModified && cached.size() == size) {
            return cached.hash();
        }

        try (InputStream is = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int read;
            while ((read = is.read(buf)) != -1) {
                digest.update(buf, 0, read);
            }
            String calculatedHash = HexFormat.of().formatHex(digest.digest());
            HASH_CACHE.put(file, new CachedHash(calculatedHash, lastModified, size));
            return calculatedHash;
        }
    }

    private static void sendError(HttpExchange exchange, int code, String message) throws IOException {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String getContentType(String fileName) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".zip")) return "application/zip";
        if (lower.endsWith(".jar")) return "application/java-archive";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".toml")) return "application/toml";
        if (lower.endsWith(".txt") || lower.endsWith(".cfg")) return "text/plain; charset=utf-8";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".ogg")) return "audio/ogg";
        return "application/octet-stream";
    }

}