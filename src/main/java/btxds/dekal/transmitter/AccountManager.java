package btxds.dekal.transmitter;

import com.mojang.authlib.GameProfile;
import net.minecraft.server.MinecraftServer;
import net.neoforged.neoforge.server.ServerLifecycleHooks;
import org.mindrot.jbcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class AccountManager {

    private static final String DB_URL = "jdbc:sqlite:accounts.db";
    private static final long SESSION_LIFETIME_MS = 14L * 24 * 60 * 60 * 1000;
    private static final long JOIN_TIMEOUT_MS = 30000;

    public static final String ROLE_PLAYER = "Player";
    public static final String ROLE_MODERATOR = "Moderator";
    public static final String ROLE_ADMIN = "Admin";

    public record AuthResponse(boolean success, String message, String token, String username, String role) {}
    public record ActionResponse(boolean success, String message) {}
    public record PendingJoin(String username, String uuid, long expiresAt) {}

    private static final Map<String, PendingJoin> PENDING_JOINS = new ConcurrentHashMap<>();

    private static class LoginAttempt {
        int failedAttempts = 0;
        int lockLevel = 0;
        long lockedUntil = 0;
    }

    private static final Map<String, LoginAttempt> LOGIN_ATTEMPTS = new ConcurrentHashMap<>();

    public static synchronized void init() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    uuid TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'Player' CHECK (role IN ('Player', 'Moderator', 'Admin')),
                    created_at INTEGER NOT NULL
                );
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE,
                    hwid TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    FOREIGN KEY (username) REFERENCES accounts(username) ON DELETE CASCADE
                );
            """);

            Main.LOGGER.info("[Dekal Transmitter] Database connected successfully.");
        } catch (SQLException e) {
            Main.LOGGER.error("[Dekal Transmitter] Database initialization error: ", e);
        }
    }

    public static AuthResponse register(String username, String password) {
        return register(username, password, "UNKNOWN");
    }

    public static AuthResponse register(String username, String password, String hwid) {
        if (!isValidUsername(username)) {
            return new AuthResponse(false, "Username must be 3-16 characters (letters, numbers, underscores only)", null, null, null);
        }
        if (password == null || password.length() < 4) {
            return new AuthResponse(false, "Password must be at least 4 characters long", null, null, null);
        }

        String checkSql = "SELECT username FROM accounts WHERE username = ?";
        String insertSql = "INSERT INTO accounts (username, password_hash, uuid, role, created_at) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = getConnection()) {
            try (PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
                checkStmt.setString(1, username);
                if (checkStmt.executeQuery().next()) {
                    return new AuthResponse(false, "Username is already taken", null, null, null);
                }
            }

            String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
            String playerUuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8)).toString();
            String assignedRole = isServerOperator(username, playerUuid) ? ROLE_ADMIN : ROLE_PLAYER;

            try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                insertStmt.setString(1, username);
                insertStmt.setString(2, hash);
                insertStmt.setString(3, playerUuid);
                insertStmt.setString(4, assignedRole);
                insertStmt.setLong(5, System.currentTimeMillis());
                insertStmt.executeUpdate();
            }

            String token = createSession(conn, username, hwid);
            return new AuthResponse(true, "Registration successful", token, username, assignedRole);

        } catch (SQLException e) {
            return new AuthResponse(false, "Database error: " + e.getMessage(), null, null, null);
        }
    }

    public static AuthResponse login(String username, String password) {
        return login(username, password, "UNKNOWN");
    }

    public static AuthResponse login(String username, String password, String hwid) {
        String lockMessage = checkLoginAllowed(username);
        if (lockMessage != null) {
            return new AuthResponse(false, lockMessage, null, null, null);
        }

        String sql = "SELECT username, password_hash, uuid, role FROM accounts WHERE username = ?";

        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if (!rs.next()) {
                String errorMsg = recordFailedAttempt(username);
                return new AuthResponse(false, errorMsg, null, null, null);
            }

            String canonicalUsername = rs.getString("username");
            String hash = rs.getString("password_hash");
            String uuid = rs.getString("uuid");
            String role = rs.getString("role");

            if (!BCrypt.checkpw(password, hash)) {
                String errorMsg = recordFailedAttempt(username);
                return new AuthResponse(false, errorMsg, null, null, null);
            }

            recordSuccessfulLogin(username);

            if (isServerOperator(canonicalUsername, uuid)) {
                role = ROLE_ADMIN;
                updateRoleInDb(conn, canonicalUsername, ROLE_ADMIN);
            } else if (ROLE_ADMIN.equalsIgnoreCase(role)) {
                role = ROLE_PLAYER;
                updateRoleInDb(conn, canonicalUsername, ROLE_PLAYER);
            }

            String token = createSession(conn, canonicalUsername, hwid);
            return new AuthResponse(true, "Login successful", token, canonicalUsername, role);

        } catch (SQLException e) {
            return new AuthResponse(false, "Database error: " + e.getMessage(), null, null, null);
        }
    }

    public static AuthResponse verifySession(String token) {
        return verifySession(token, null);
    }

    public static AuthResponse verifySession(String token, String hwid) {
        if (token == null || token.isBlank()) {
            return new AuthResponse(false, "Token is empty", null, null, null);
        }

        String sql = """
            SELECT a.username, a.uuid, s.hwid, s.expires_at, a.role 
            FROM sessions s 
            JOIN accounts a ON s.username = a.username 
            WHERE s.token = ?
        """;

        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, token);
            ResultSet rs = stmt.executeQuery();

            if (!rs.next()) {
                return new AuthResponse(false, "Session not found", null, null, null);
            }

            long expiresAt = rs.getLong("expires_at");
            if (System.currentTimeMillis() > expiresAt) {
                deleteSession(conn, token);
                return new AuthResponse(false, "Session has expired", null, null, null);
            }

            if (hwid != null) {
                String storedHwid = rs.getString("hwid");
                if (!storedHwid.equalsIgnoreCase(hwid)) {
                    deleteSession(conn, token);
                    return new AuthResponse(false, "Hardware mismatch. Session invalidated", null, null, null);
                }
            }

            String username = rs.getString("username");
            String uuid = rs.getString("uuid");
            String role = rs.getString("role");

            if (isServerOperator(username, uuid)) {
                role = ROLE_ADMIN;
                updateRoleInDb(conn, username, ROLE_ADMIN);
            } else if (ROLE_ADMIN.equalsIgnoreCase(role)) {
                role = ROLE_PLAYER;
                updateRoleInDb(conn, username, ROLE_PLAYER);
            }

            return new AuthResponse(true, "Session is valid", token, username, role);

        } catch (SQLException e) {
            return new AuthResponse(false, "Database error", null, null, null);
        }
    }

    public static boolean processClientJoin(String accessToken, String selectedProfile, String serverId) {
        AuthResponse auth = verifySession(accessToken);
        if (!auth.success()) return false;

        String accountUuid = getAccountUuid(auth.username());
        if (accountUuid == null) return false;

        String strippedAccountUuid = accountUuid.replace("-", "");
        String strippedSelectedProfile = selectedProfile.replace("-", "");

        if (!strippedAccountUuid.equalsIgnoreCase(strippedSelectedProfile)) return false;

        PENDING_JOINS.put(serverId, new PendingJoin(auth.username(), strippedAccountUuid, System.currentTimeMillis() + JOIN_TIMEOUT_MS));
        return true;
    }

    public static PendingJoin processServerHasJoined(String username, String serverId) {
        PendingJoin join = PENDING_JOINS.remove(serverId);
        if (join == null) return null;
        if (System.currentTimeMillis() > join.expiresAt()) return null;
        if (!join.username().equalsIgnoreCase(username)) return null;

        return join;
    }

    public static String getAccountUuid(String username) {
        String sql = "SELECT uuid FROM accounts WHERE username = ?";
        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("uuid");
            }
        } catch (SQLException ignored) {}
        return null;
    }

    public static ActionResponse setRole(String username, String role) {
        String normalizedRole;
        if (ROLE_PLAYER.equalsIgnoreCase(role)) {
            normalizedRole = ROLE_PLAYER;
        } else if (ROLE_MODERATOR.equalsIgnoreCase(role)) {
            normalizedRole = ROLE_MODERATOR;
        } else if (ROLE_ADMIN.equalsIgnoreCase(role)) {
            normalizedRole = ROLE_ADMIN;
        } else {
            return new ActionResponse(false, "Invalid role. Allowed roles: Player, Moderator, Admin");
        }

        String sql = "UPDATE accounts SET role = ? WHERE username = ?";

        try (Connection conn = getConnection(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, normalizedRole);
            stmt.setString(2, username);
            int rows = stmt.executeUpdate();

            if (rows == 0) {
                return new ActionResponse(false, "Account not found");
            }

            return new ActionResponse(true, "Role updated to " + normalizedRole);

        } catch (SQLException e) {
            return new ActionResponse(false, "Database error: " + e.getMessage());
        }
    }

    public static ActionResponse changePassword(String username, String newPassword) {
        if (newPassword == null || newPassword.length() < 4) {
            return new ActionResponse(false, "Password must be at least 4 characters long");
        }

        String updateSql = "UPDATE accounts SET password_hash = ? WHERE username = ?";

        try (Connection conn = getConnection()) {
            String newHash = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));

            try (PreparedStatement stmt = conn.prepareStatement(updateSql)) {
                stmt.setString(1, newHash);
                stmt.setString(2, username);
                int rows = stmt.executeUpdate();

                if (rows == 0) {
                    return new ActionResponse(false, "Account not found");
                }
            }

            invalidateUserSessions(conn, username);
            return new ActionResponse(true, "Password updated successfully");

        } catch (SQLException e) {
            return new ActionResponse(false, "Database error: " + e.getMessage());
        }
    }

    public static ActionResponse deleteAccount(String username) {
        String deleteSql = "DELETE FROM accounts WHERE username = ?";

        try (Connection conn = getConnection()) {
            invalidateUserSessions(conn, username);

            try (PreparedStatement stmt = conn.prepareStatement(deleteSql)) {
                stmt.setString(1, username);
                int rows = stmt.executeUpdate();

                if (rows == 0) {
                    return new ActionResponse(false, "Account not found");
                }
            }

            return new ActionResponse(true, "Account deleted successfully");

        } catch (SQLException e) {
            return new ActionResponse(false, "Database error: " + e.getMessage());
        }
    }

    private static synchronized String checkLoginAllowed(String username) {
        LoginAttempt attempt = LOGIN_ATTEMPTS.get(username.toLowerCase());
        if (attempt == null) {
            return null;
        }

        long now = System.currentTimeMillis();
        if (now < attempt.lockedUntil) {
            long remainingMinutes = Math.max(1, (attempt.lockedUntil - now + 59999) / 60000);
            return "Too many failed attempts. Locked for " + remainingMinutes + " minute(s).";
        }

        return null;
    }

    private static synchronized String recordFailedAttempt(String username) {
        String key = username.toLowerCase();
        LoginAttempt attempt = LOGIN_ATTEMPTS.computeIfAbsent(key, k -> new LoginAttempt());
        long now = System.currentTimeMillis();

        if (now >= attempt.lockedUntil && attempt.lockedUntil > 0) {
            attempt.lockedUntil = 0;
        }

        attempt.failedAttempts++;

        if (attempt.failedAttempts >= 10) {
            long durationMs;
            if (attempt.lockLevel == 0) {
                durationMs = 10L * 60 * 1000;
                attempt.lockLevel = 1;
            } else {
                durationMs = 60L * 60 * 1000;
                attempt.lockLevel = 2;
            }

            attempt.lockedUntil = now + durationMs;
            attempt.failedAttempts = 0;
            long minutes = durationMs / 60000;
            return "Too many failed attempts. Account locked for " + minutes + " minutes.";
        }

        return "Invalid username or password. Remaining attempts: " + (10 - attempt.failedAttempts);
    }

    private static synchronized void recordSuccessfulLogin(String username) {
        LOGIN_ATTEMPTS.remove(username.toLowerCase());
    }

    private static boolean isServerOperator(String username, String uuidStr) {
        try {
            MinecraftServer server = ServerLifecycleHooks.getCurrentServer();
            if (server != null && uuidStr != null) {
                GameProfile profile = new GameProfile(UUID.fromString(uuidStr), username);
                return server.getPlayerList().isOp(new net.minecraft.server.players.NameAndId(profile));
            }
        } catch (Throwable ignored) {}

        try {
            Path opsPath = Path.of("ops.json");
            if (Files.exists(opsPath)) {
                String content = Files.readString(opsPath, StandardCharsets.UTF_8).toLowerCase();
                if (content.contains("\"name\": \"" + username.toLowerCase() + "\"")) {
                    return true;
                }
                if (uuidStr != null && content.contains("\"uuid\": \"" + uuidStr.toLowerCase() + "\"")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {}

        return false;
    }

    private static void updateRoleInDb(Connection conn, String username, String role) {
        String sql = "UPDATE accounts SET role = ? WHERE username = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, role);
            stmt.setString(2, username);
            stmt.executeUpdate();
        } catch (SQLException ignored) {}
    }

    private static String createSession(Connection conn, String username, String hwid) throws SQLException {
        String token = UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + SESSION_LIFETIME_MS;

        String sql = "INSERT INTO sessions (token, username, hwid, expires_at) VALUES (?, ?, ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, token);
            stmt.setString(2, username);
            stmt.setString(3, hwid != null ? hwid : "UNKNOWN");
            stmt.setLong(4, expiresAt);
            stmt.executeUpdate();
        }
        return token;
    }

    private static void deleteSession(Connection conn, String token) {
        try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM sessions WHERE token = ?")) {
            stmt.setString(1, token);
            stmt.executeUpdate();
        } catch (SQLException ignored) {}
    }

    private static void invalidateUserSessions(Connection conn, String username) {
        try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM sessions WHERE username = ?")) {
            stmt.setString(1, username);
            stmt.executeUpdate();
        } catch (SQLException ignored) {}
    }

    private static boolean isValidUsername(String username) {
        return username != null && username.matches("^[a-zA-Z0-9_]{3,16}$");
    }

    private static Connection getConnection() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException ignored) {}

        Driver driver = new org.sqlite.JDBC();
        return driver.connect(DB_URL, new java.util.Properties());
    }

}