package de.rayzs.pat.utils;

import de.rayzs.pat.api.storage.Storage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class CommunicationPacketsSecurityTest {

    private static final String TOKEN = "test-token-6d21af0b-e44e-4c94-9920-7ecbd96243e1";
    private static final UUID BACKEND_ID = UUID.fromString("28ef48c0-62cc-4f25-b2f0-6fb53d2dd61b");
    private static final UUID OTHER_BACKEND_ID = UUID.fromString("dfe05064-55c9-4b3b-a65f-d6beaeb0b9af");

    private String previousToken;

    @BeforeEach
    void setUp() {
        previousToken = Storage.TOKEN;
        Storage.TOKEN = TOKEN;
    }

    @AfterEach
    void tearDown() {
        Storage.TOKEN = previousToken;
    }

    @Test
    void normalPacketRoundTripsWithMatchingBackendContext() {
        UUID playerId = UUID.fromString("7c9f9835-cf72-49c1-aaf0-e4c9853cf7fa");
        var original = new CommunicationPackets.Proxy2Backend.ExecutePlayerCommandPacket(
                playerId, "warp spawn"
        );

        byte[] encoded = CommunicationPackets.preparePacket(original, BACKEND_ID);
        Object decoded = CommunicationPackets.readPacket(encoded, BACKEND_ID);

        assertNotNull(encoded);
        assertEquals(original, decoded);
        assertTrue(CommunicationPackets.isP2BPacket(decoded));
        assertFalse(CommunicationPackets.isInitialPacket(decoded));
    }

    @Test
    void initialHandshakePacketRoundTripsIndependentlyOfBackendContext() {
        var original = new CommunicationPackets.Backend2Proxy.IdentityRequestPacket(BACKEND_ID);

        byte[] encoded = CommunicationPackets.preparePacket(original, BACKEND_ID);

        assertNotNull(encoded);
        assertTrue(CommunicationPackets.isInitialPacket(encoded));
        assertEquals(original, CommunicationPackets.readPacket(encoded, OTHER_BACKEND_ID));
    }

    @Test
    void samePlaintextProducesDifferentCiphertextBecauseNonceIsRandom() {
        var packet = new CommunicationPackets.Proxy2Backend.ConsoleMessagePacket("same message");

        byte[] first = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        byte[] second = CommunicationPackets.preparePacket(packet, BACKEND_ID);

        assertNotNull(first);
        assertNotNull(second);
        assertFalse(Arrays.equals(first, second), "AES-GCM packets must use fresh nonces");
        assertEquals(packet, CommunicationPackets.readPacket(first, BACKEND_ID));
        assertEquals(packet, CommunicationPackets.readPacket(second, BACKEND_ID));
    }

    @Test
    void tamperingWithCiphertextIsRejected() {
        var packet = new CommunicationPackets.Proxy2Backend.ExecuteConsoleCommandPacket("say secure");
        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(encoded);

        byte[] tampered = encoded.clone();
        tampered[tampered.length - 1] ^= 0x01;

        assertNull(CommunicationPackets.readPacket(tampered, BACKEND_ID));
    }

    @Test
    void tamperingWithAuthenticatedHeaderIsRejected() {
        var packet = new CommunicationPackets.Proxy2Backend.KeepAliveResponsePacket();
        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(encoded);

        byte[] tampered = encoded.clone();
        tampered[1] = 0; // claim this normal packet is an initial packet

        assertNull(CommunicationPackets.readPacket(tampered, BACKEND_ID));
    }

    @Test
    void wrongBackendUuidCannotDecryptNormalPacket() {
        var packet = new CommunicationPackets.Backend2Proxy.AnnouncePlayerPermissionChanges(UUID.randomUUID());
        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);

        assertNotNull(encoded);
        assertNull(CommunicationPackets.readPacket(encoded, OTHER_BACKEND_ID));
        assertEquals(packet, CommunicationPackets.readPacket(encoded, BACKEND_ID));
    }

    @Test
    void wrongStorageTokenCannotDecryptPacket() {
        var packet = new CommunicationPackets.Proxy2Backend.NotificationPacket(
                UUID.randomUUID(), "help"
        );
        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(encoded);

        Storage.TOKEN = "different-token-that-must-not-authenticate";
        assertNull(CommunicationPackets.readPacket(encoded, BACKEND_ID));
    }

    @Test
    void truncatedAndInvalidFramesAreRejectedWithoutThrowing() {
        assertDoesNotThrow(() -> {
            assertNull(CommunicationPackets.readPacket(null, BACKEND_ID));
            assertNull(CommunicationPackets.readPacket(new byte[0], BACKEND_ID));
            assertNull(CommunicationPackets.readPacket(new byte[8], BACKEND_ID));
        });

        var packet = new CommunicationPackets.Backend2Proxy.KeepAlivePacket();
        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(encoded);

        for (int length : new int[]{1, 2, 5, 13, encoded.length - 1}) {
            byte[] truncated = Arrays.copyOf(encoded, length);
            assertDoesNotThrow(() -> assertNull(CommunicationPackets.readPacket(truncated, BACKEND_ID)));
        }
    }

    @Test
    void invalidProtocolVersionIsRejected() {
        var packet = new CommunicationPackets.Backend2Proxy.KeepAlivePacket();
        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(encoded);

        byte[] wrongVersion = encoded.clone();
        wrongVersion[0]++;

        assertNull(CommunicationPackets.readPacket(wrongVersion, BACKEND_ID));
    }

    @Test
    void blankTokenDisablesEncodingAndDecoding() {
        var packet = new CommunicationPackets.Backend2Proxy.KeepAlivePacket();
        byte[] valid = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(valid);

        Storage.TOKEN = "   ";
        assertNull(CommunicationPackets.preparePacket(packet, BACKEND_ID));
        assertNull(CommunicationPackets.readPacket(valid, BACKEND_ID));
    }

    @Test
    void representativePacketTypesPreserveTheirPayloads() {
        UUID player = UUID.fromString("c112a6b7-82ec-4120-a4f6-f7c6d0953eef");
        Set<UUID> players = new HashSet<>(Set.of(
                player,
                UUID.fromString("f59bad95-cd4c-4fc2-a76b-834f38de2447")
        ));

        CommunicationPackets.PATPacket[] packets = {
                new CommunicationPackets.Proxy2Backend.UpdatePacket(null),
                new CommunicationPackets.Proxy2Backend.UpdatePacket(player),
                new CommunicationPackets.Proxy2Backend.IdentityPacket(BACKEND_ID, "survival"),
                new CommunicationPackets.Proxy2Backend.ExecuteConsoleCommandPacket("list"),
                new CommunicationPackets.Proxy2Backend.ConsoleMessagePacket("hello"),
                new CommunicationPackets.Backend2Proxy.IdentityResponsePacket(BACKEND_ID),
                new CommunicationPackets.Backend2Proxy.DataSyncReceivedPacket(),
                new CommunicationPackets.Backend2Proxy.AnnounceGroupPermissionChanges(players)
        };

        for (CommunicationPackets.PATPacket packet : packets) {
            byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
            assertNotNull(encoded, () -> "Failed to encode " + packet.getClass().getSimpleName());
            assertEquals(packet, CommunicationPackets.readPacket(encoded, BACKEND_ID),
                    () -> "Round-trip mismatch for " + packet.getClass().getSimpleName());
        }
    }

    @Test
    void normalPacketRequiresBackendContext() {
        var packet = new CommunicationPackets.Backend2Proxy.KeepAlivePacket();

        assertNull(CommunicationPackets.preparePacket(packet, null));

        byte[] encoded = CommunicationPackets.preparePacket(packet, BACKEND_ID);
        assertNotNull(encoded);
        assertNull(CommunicationPackets.readPacket(encoded, null));
    }

    @Test
    void oversizedWirePacketIsRejectedBeforeDecryption() {
        // 64 KiB plaintext + 2-byte header + 12-byte nonce + 16-byte GCM tag.
        byte[] oversized = new byte[(64 * 1024) + 2 + 12 + 16 + 1];
        oversized[0] = 2;
        oversized[1] = 1;

        assertNull(CommunicationPackets.readPacket(oversized, BACKEND_ID));
    }
}
