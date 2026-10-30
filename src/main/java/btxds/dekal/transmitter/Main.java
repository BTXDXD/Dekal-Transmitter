package btxds.dekal.transmitter;

import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.server.ServerStartingEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import org.slf4j.Logger;

import com.mojang.logging.LogUtils;

import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.ModContainer;

@Mod(Main.MODID)
public class Main {

    public static final String MODID = "dekaltransmitter";
    public static final Logger LOGGER = LogUtils.getLogger();

    public Main(IEventBus modEventBus, ModContainer modContainer) {
        NeoForge.EVENT_BUS.addListener(this::onServerStarting);
        NeoForge.EVENT_BUS.addListener(this::onServerStopping);
    }

    private void onServerStarting(ServerStartingEvent event) {
        LOGGER.info("[Dekal Transmitter] Initialize");
        FileServer.start();
    }

    private void onServerStopping(ServerStoppingEvent event) {
        LOGGER.info("[Dekal Transmitter] Stopping");
        FileServer.stop();
    }

}
