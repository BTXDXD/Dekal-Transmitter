package btxds.dekal.transmitter.mixin;

import btxds.dekal.transmitter.AccountManager;
import btxds.dekal.transmitter.Main;
import com.mojang.authlib.GameProfile;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.login.ServerboundKeyPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import net.minecraft.util.Crypt;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.UUID;

@Mixin(ServerLoginPacketListenerImpl.class)
public abstract class MixinServerLogin {

    @Shadow @Final MinecraftServer server;
    @Shadow @Final Connection connection;
    @Shadow private byte[] challenge;
    @Shadow private String requestedUsername;
    @Shadow private String serverId;

    @Shadow abstract void startClientVerification(GameProfile profile);
    @Shadow public abstract void disconnect(Component reason);

    @Inject(method = "handleKey", at = @At("HEAD"), cancellable = true)
    private void onHandleKey(ServerboundKeyPacket packet, CallbackInfo ci) {
        ci.cancel();

        try {
            PrivateKey privateKey = this.server.getKeyPair().getPrivate();

            if (!packet.isChallengeValid(this.challenge, privateKey)) {
                throw new IllegalStateException("Protocol error");
            }

            SecretKey secretKey = packet.getSecretKey(privateKey);
            this.connection.setEncryptionKey(
                    Crypt.getCipher(javax.crypto.Cipher.DECRYPT_MODE, secretKey),
                    Crypt.getCipher(javax.crypto.Cipher.ENCRYPT_MODE, secretKey)
            );

            String digest = (new BigInteger(Crypt.digestData(
                    this.serverId,
                    this.server.getKeyPair().getPublic(),
                    secretKey
            ))).toString(16);

            Main.LOGGER.info("[Dekal Transmitter] Verifying session for {} with digest {}", this.requestedUsername, digest);

            AccountManager.PendingJoin join = AccountManager.processServerHasJoined(this.requestedUsername, digest);

            if (join != null) {
                Main.LOGGER.info("[Dekal Transmitter] Player {} authorized successfully!", this.requestedUsername);

                UUID uuid = UUID.fromString(
                        join.uuid().replaceFirst("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5")
                );
                GameProfile authorizedProfile = new GameProfile(uuid, join.username());

                this.startClientVerification(authorizedProfile);
            } else {
                Main.LOGGER.warn("[Dekal Transmitter] Authorization failed for {}: invalid session!", this.requestedUsername);
                this.disconnect(Component.translatable("multiplayer.disconnect.unverified_username"));
            }

        } catch (Exception e) {
            Main.LOGGER.error("[Dekal Transmitter] Failed to process encryption / auth: ", e);
            this.disconnect(Component.literal("Authentication error"));
        }
    }

}