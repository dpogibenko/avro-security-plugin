package com.sprocketry.avro.security;

import org.apache.avro.AvroRemoteException;
import org.apache.avro.Protocol;
import org.apache.avro.ipc.LocalTransceiver;
import org.apache.avro.ipc.generic.GenericResponder;
import org.apache.avro.ipc.specific.SpecificRequestor;
import org.apache.avro.security.Ticket;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.ByteBuffer;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * <code>AuthenticationPluginTest</code>
 */
public class AuthenticationPluginTest {

    private MockResponder testResponder;
    private SpecificRequestor testRequestor;
    private Foo client;
    private Protocol protocol;

    private AuthenticationPlugin clientPlugin;
    private AuthenticationPlugin serverPlugin;

    private String username = "rredford";
    private String password = "afghanistanbananastand";
    private Ticket ticket;
    private Bar bar;

    @Test
    public void authenticationDetailsGetSentAsMetadata() throws Exception {

        AuthenticationStrategy mockStrategy = setupValidMockResponse();
        client.foo(bar);
        verify(mockStrategy).authenticate(eq(username), eq(password), any(Protocol.Message.class));
        client.foo(bar);
        verify(mockStrategy).verifyTicket(any(Ticket.class), any(Protocol.Message.class));
        testResponder.assertIsSatisfied();
    }

    @Test
    public void authenticationFailureGetsReturnedAsMetadata() throws Exception {

        AuthenticationStrategy mockStrategy = mock(AuthenticationStrategy.class);
        when(mockStrategy.authenticate(eq(username), eq(password), any(Protocol.Message.class)))
                .thenThrow(new RuntimeException("Authentication error: Incorrect credentials"));
        serverPlugin.setAuthenticationStrategy(mockStrategy);

        makeFailingRequest();
    }

    @Test
    public void errorWhenPluginNotOnBothSides() throws Exception {
        setupValidMockResponse();
        testRequestor = new SpecificRequestor(Foo.class, new LocalTransceiver(testResponder));
        client = SpecificRequestor.getClient(Foo.class, testRequestor);
        makeFailingRequest();
    }

    @Test
    public void errorWhenNoStrategyPresent() throws Exception {
        client.foo(bar);
        Assert.fail();
    }

    @Before
    public void setupPlugin() throws Exception {
        protocol = Protocol.parse(new File("src/test/avro/foo.avpr"));
        testResponder = new MockResponder(protocol);
        testRequestor = new SpecificRequestor(Foo.class, new LocalTransceiver(testResponder));
        client = SpecificRequestor.getClient(Foo.class, testRequestor);

        clientPlugin = new AuthenticationPlugin();
        serverPlugin = new AuthenticationPlugin();
        testRequestor.addRPCPlugin(clientPlugin);
        testResponder.addRPCPlugin(serverPlugin);

        clientPlugin.setUsername(username);
        clientPlugin.setPassword(password);

        ticket = new Ticket();
        ticket.setDigest(ByteBuffer.wrap("abbaabbacdcdee".getBytes()));
        ticket.setExpiry(12345L);

        bar = new Bar();
        bar.x = 12345;
    }

    private void makeFailingRequest() throws AvroRemoteException, Baz {
        client.foo(bar);
        Assert.fail();
    }

    private AuthenticationStrategy setupValidMockResponse() {
        AuthenticationStrategy mockStrategy = mock(AuthenticationStrategy.class);
        when(mockStrategy.authenticate(eq(username), eq(password), any(Protocol.Message.class)))
                .thenReturn(ticket);
        serverPlugin.setAuthenticationStrategy(mockStrategy);
        return mockStrategy;
    }

    private static class MockResponder extends GenericResponder {

        private boolean called;

        MockResponder(Protocol protocol) {
            super(protocol);
        }

        public Object respond(Protocol.Message message, Object request) throws Exception {
            called = true;
            return 4567;
        }

        public void assertIsSatisfied() {
            Assert.assertTrue(called);
        }
    }
}
