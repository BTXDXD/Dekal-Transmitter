package btxds.dekal.transmitter;

import java.nio.file.Path;

public class Config {

    public static final int SERVER_FILEHOST_PORT = 25999;
    public static final Path SERVER_FILEHOST_DIR = Path.of("launcher").toAbsolutePath().normalize();

}