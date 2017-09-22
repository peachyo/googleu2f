package com.google.u2f.conf;

import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import com.google.u2f.resource.FidoU2fResource;


@Configuration
@Component
public class JerseyConfig extends ResourceConfig {

	public JerseyConfig() {
		register(FidoU2fResource.class);
	}

}
