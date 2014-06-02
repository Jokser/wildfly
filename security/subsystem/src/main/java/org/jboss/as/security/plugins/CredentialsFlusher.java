package org.jboss.as.security.plugins;

import io.undertow.security.api.NotificationReceiver;
import io.undertow.security.api.SecurityNotification;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionListener;
import io.undertow.util.Sessions;
import org.jboss.security.CacheableManager;

import java.security.Principal;

/**
 * Catches authenticate event and register session listener, which flushes credentials
 * when session destroying
 *
 * @author Pavel Kovalenko
 */
public class CredentialsFlusher implements NotificationReceiver {

    private static final String PRINCIPAL_SESSION_ATTRIBUTE = CredentialsFlusher.class.getName() + ".principal";

    private CacheableManager<?, Principal> authenticationManager;

    public CredentialsFlusher(CacheableManager<?, Principal> authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void handleNotification(SecurityNotification notification) {
        SecurityNotification.EventType eventType = notification.getEventType();
        switch (eventType) {
            case AUTHENTICATED:
                Session session = Sessions.getSession(notification.getExchange());
                if (session != null) {
                    session.setAttribute(PRINCIPAL_SESSION_ATTRIBUTE, notification.getAccount().getPrincipal());
                    session.getSessionManager().registerSessionListener(new FlushCredentialsListener());
                }
                break;
            case LOGGED_OUT:
                break;
        }
    }

    final class FlushCredentialsListener implements SessionListener {

        @Override
        public void sessionCreated(Session session, HttpServerExchange httpServerExchange) {

        }

        @Override
        public void sessionDestroyed(Session session, HttpServerExchange httpServerExchange, SessionDestroyedReason sessionDestroyedReason) {
            Principal principal = (Principal) session.getAttribute(PRINCIPAL_SESSION_ATTRIBUTE);
            if (principal != null) {
                authenticationManager.flushCache(principal);
            }
        }

        @Override
        public void attributeAdded(Session session, String s, Object o) {

        }

        @Override
        public void attributeUpdated(Session session, String s, Object o, Object o2) {

        }

        @Override
        public void attributeRemoved(Session session, String s, Object o) {

        }

        @Override
        public void sessionIdChanged(Session session, String s) {

        }
    }

}
