package com.google.u2f.resource;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonObject;
import com.google.u2f.U2FException;
import com.google.u2f.server.ChallengeGenerator;
import com.google.u2f.server.DataStore;
import com.google.u2f.server.SessionIdGenerator;
import com.google.u2f.server.U2FServer;
import com.google.u2f.server.data.SecurityKeyData;
import com.google.u2f.server.impl.BouncyCastleCrypto;
import com.google.u2f.server.impl.MemoryDataStore;
import com.google.u2f.server.impl.U2FServerReferenceImpl;
import com.google.u2f.server.messages.RegistrationRequest;
import com.google.u2f.server.messages.RegistrationResponse;
import com.google.u2f.server.messages.SignResponse;
import com.google.u2f.server.messages.U2fSignRequest;

@Path("/fidou2f/v1")
public class FidoU2fResource {

	@GET
	@Path("regRequest/{username}")
	@Produces(MediaType.APPLICATION_JSON)
	public String register(@PathParam("username") String username) {

		if (username == null) {
			throw new BadRequestException("Username cannot be null");
		}
		RegistrationRequest registrationRequest;
		try {
			registrationRequest = u2fServer.getRegistrationRequest(username, "http://localhost:8080");
		} catch (U2FException e) {
			throw new InternalServerErrorException(e.getMessage());
		}

		JsonObject enrollServerData = new JsonObject();
		enrollServerData.addProperty("appId", registrationRequest.getAppId());
		enrollServerData.addProperty("challenge", registrationRequest.getChallenge());
		enrollServerData.addProperty("version", registrationRequest.getVersion());
		enrollServerData.addProperty("sessionId", registrationRequest.getSessionId());

		return enrollServerData.toString();
	}

	@POST
	@Path("regResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public SecurityKeyData generateBody(RegistrationResponse registrationResponse) {
		try {
			SecurityKeyData tokenData = u2fServer.processRegistrationResponse(registrationResponse,
					System.currentTimeMillis());
			return tokenData;
		} catch (U2FException e) {
			throw new InternalServerErrorException(e.getMessage());
		}
	}

	@GET
	@Path("authRequest/{username}")
	@Produces(MediaType.APPLICATION_JSON)
	public String getAuthForAppIdReq(@PathParam("username") String username) {
		if (username == null) {
			throw new BadRequestException("Username cannot be null");
		}

		String appId = "http://localhost:8080";
		U2fSignRequest signRequest;
		try {
			signRequest = u2fServer.getSignRequest(username, appId);
		} catch (U2FException e) {
			throw new InternalServerErrorException(e.getMessage());
		}
		JsonObject result = new JsonObject();
		result.addProperty("challenge", signRequest.getChallenge());
		result.addProperty("appId", appId);
		result.add("registeredKeys", signRequest.getRegisteredKeysAsJson(appId));

		return result.toString();
	}

	@POST
	@Path("authResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public void generateBody(SignResponse signResponse) {
		try {
			u2fServer.processSignResponse(signResponse);
			System.out.println("Success!!!");
		} catch (U2FException e) {
			System.out.println("Failure: " + e.toString());
		}
	}
	
	  private final Object lock = new Object();
	  private final U2FServer u2fServer;

	  private long sessionIdCounter = 0;

	  public FidoU2fResource() {
	    ChallengeGenerator challengeGenerator = new ChallengeGenerator() {
	      @Override
	      public byte[] generateChallenge(String accountName) {
	        try {
	          return Hex.decodeHex("1234".toCharArray());
	        } catch (DecoderException e) {
	          throw new RuntimeException(e);
	        }
	      }
	    };

	    SessionIdGenerator sessionIdGenerator = new SessionIdGenerator() {
	      @Override
	      public String generateSessionId(String accountName) {
	        return new StringBuilder()
	          .append("sessionId_")
	          .append(sessionIdCounter++)
	          .append("_")
	          .append(accountName)
	          .toString();
	      }
	    };

	    X509Certificate trustedCertificate;
	    try {
	      trustedCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
	          .generateCertificate(new ByteArrayInputStream(Hex.decodeHex((
	              "308201433081eaa0030201020209012333009941964658300a06082a8648ce3d"
	                  + "040302301b3119301706035504031310476e756262792048534d2043412030"
	                  + "303022180f32303132303630313030303030305a180f323036323035333132"
	                  + "33353935395a30303119301706035504031310476f6f676c6520476e756262"
	                  + "7920763031133011060355042d030a00012333009941964658305930130607"
	                  + "2a8648ce3d020106082a8648ce3d03010703420004aabc1b97a7c391f8b1fe"
	                  + "5280a65cf27890409bdc392e181ff00ccf39599461d583f3351b21602cf99e"
	                  + "2fe71e7f838658b42df49f06b8446d375d2aaaa8e317a1300a06082a8648ce"
	                  + "3d0403020348003045022037788207c2239373b289169cfd3500b54fe92903"
	                  + "e6772ea995cd2ce4a670fba5022100dfbfe7da528600be0d6125060d029f40"
	                  + "c647bc053e35226fffb66cd7f4609b49").toCharArray())));
	    } catch (CertificateException e) {
	      throw new RuntimeException(e);
	    } catch (DecoderException e) {
	      throw new RuntimeException(e);
	    }
	    DataStore dataStore = new MemoryDataStore(sessionIdGenerator);
	    dataStore.addTrustedCertificate(trustedCertificate);

	    // this implementation will only accept signatures from http://localhost:8080
	    u2fServer = new U2FServerReferenceImpl(challengeGenerator, dataStore,
	        new BouncyCastleCrypto(), ImmutableSet.of("http://localhost:8080"));
	  }
}