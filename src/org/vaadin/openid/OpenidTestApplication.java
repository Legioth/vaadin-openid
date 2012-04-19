package org.vaadin.openid;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import org.vaadin.openid.OpenIdHandler.UserAttribute;

import com.vaadin.Application;
import com.vaadin.ui.HorizontalLayout;
import com.vaadin.ui.Label;
import com.vaadin.ui.Link;
import com.vaadin.ui.Root;
import com.vaadin.ui.VerticalLayout;

public class OpenidTestApplication extends Application.LegacyApplication {

    @Override
    public void init() {
        VerticalLayout container = new VerticalLayout();
        container.setSpacing(true);
        container.setMargin(true);

        Root.LegacyWindow mainWindow = new Root.LegacyWindow("OpenId test",
                container);
        setMainWindow(mainWindow);

        final OpenIdHandler openIdHandler = new OpenIdHandler(this);
        openIdHandler.setRequestedAttributes(UserAttribute.values());

        final HorizontalLayout linkHolder = new HorizontalLayout();
        linkHolder.setSpacing(true);
        linkHolder
                .addComponent(createLoginLink(openIdHandler,
                        "https://www.google.com/accounts/o8/id",
                        "Log in using Google"));
        linkHolder.addComponent(createLoginLink(openIdHandler,
                "https://me.yahoo.com", "Log in using Yahoo"));

        container.addComponent(linkHolder);

        openIdHandler.addListener(new OpenIdHandler.OpenIdLoginListener() {
            public void onLogin(String id, Map<UserAttribute, String> userInfo) {
                Root.LegacyWindow window = getMainWindow();
                window.removeComponent(linkHolder);
                window.addComponent(new Label("Logged in identity: " + id));
                Set<UserAttribute> missingFields = EnumSet
                        .allOf(UserAttribute.class);
                for (UserAttribute field : userInfo.keySet()) {
                    window.addComponent(new Label(field + ": "
                            + userInfo.get(field)));
                    missingFields.remove(field);
                }
                for (UserAttribute registrationFields : missingFields) {
                    window.addComponent(new Label(registrationFields
                            + " not provided"));
                }

                openIdHandler.close();
            }

            public void onCancel() {
                getMainWindow().removeComponent(linkHolder);
                getMainWindow().addComponent(
                        new Label("Too sad you didn't want to log in."));

                openIdHandler.close();
            }
        });
    }

    private static Link createLoginLink(OpenIdHandler openIdHandler, String id,
            String caption) {
        return new Link(caption, openIdHandler.getLoginResource(id),
                "openidLogin", 600, 400, 0);
    }
}
