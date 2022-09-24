package com.example.drive.controller;

import com.example.drive.dto.*;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.googleapis.services.CommonGoogleClientRequestInitializer;
import com.google.api.client.googleapis.services.GoogleClientRequestInitializer;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.Drive.Changes;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.ChangeList;
import com.google.api.services.drive.model.Channel;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.drive.model.Permission;
import com.google.api.services.drive.model.StartPageToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.api.client.json.gson.*;


@Controller
public class HomepageController{
	private static HttpTransport HTTP_TRANSPORT=new NetHttpTransport();
	private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
	private static final List<String> SCOPES = Arrays.asList(DriveScopes.DRIVE,"https://www.googleapis.com/auth/drive.install");
	public static final String USER_IDENTIFIER_KEY="MyDummyUser";
	@Value("${google.oauth.callback.uri}")
	private String CALLBACK_URI;
	@Value("${google.secret.key.path}")
	private Resource gdSecretKeys;
	@Value("${google.credentials.folder.path}")
	private Resource credentialsFolder;
	private GoogleAuthorizationCodeFlow flow;
	@Value("${google.service.account.key}")
	private Resource serviceAccountKey;
	
	@PostConstruct
	public void init() throws IOException {
		GoogleClientSecrets secrets=GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(gdSecretKeys.getInputStream()));
		flow=new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT,JSON_FACTORY,secrets,SCOPES)
				.setDataStoreFactory(new FileDataStoreFactory(credentialsFolder.getFile())).build();
	}
	
	@GetMapping(value= {"/"})
	public String showHomePage() throws IOException {
		boolean isUserAuthenticated=false;
		
		Credential credential=flow.loadCredential(USER_IDENTIFIER_KEY);
		if(credential!=null) {
			boolean tokenValid=credential.refreshToken();
			if(tokenValid) {
				isUserAuthenticated=true;
			}
		}
		
		return isUserAuthenticated?"dashboard.html":"index.html";
	}
	
	@GetMapping(value= {"/googlesignin"})
	public void doGoogleSignIn(HttpServletResponse response) throws IOException {
		GoogleAuthorizationCodeRequestUrl url=flow.newAuthorizationUrl();
		String redirectURL=url.setRedirectUri(CALLBACK_URI).setAccessType("offline").build();
		response.sendRedirect(redirectURL);
	}
	@GetMapping(value= {"/oauth"})
	public String saveAuthorizationCode(HttpServletRequest request) throws IOException {
		System.out.println("Inside saveAuthorizationCode");
		String code =request.getParameter("code");

		if(code!=null) {
			saveToken(code);
			System.out.println("code not null");
			return "dashboard.html";
		}
		return "index.html";
	}
	@GetMapping(value = { "/create" })
	public void createFile(HttpServletResponse response) throws Exception {
		Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred)
				.setApplicationName("DriveAPI").build();

		File file = new File();
		file.setName("profile.jpg");

		FileContent content = new FileContent("image/jpeg", new java.io.File("/Users/tanujabhatnagar/Downloads/google_sign_in.png"));
		File uploadedFile = drive.files().create(file, content).setFields("id").execute();

		String fileReference = String.format("{fileID: '%s'}", uploadedFile.getId());
		response.getWriter().write(fileReference);
	}
	@GetMapping(value = { "/uploadinfolder" })
	public void uploadFileInFolder(HttpServletResponse response) throws Exception {
		Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred)
				.setApplicationName("DriveAPI").build();

		File file = new File();
		file.setName("digit.jpg");
		file.setParents(Arrays.asList("1"));

		FileContent content = new FileContent("image/jpeg", new java.io.File("/Users/tanujabhatnagar/Downloads/google_sign_in.png"));
		File uploadedFile = drive.files().create(file, content).setFields("id").execute();
		String fileReference = String.format("{fileID: '%s'}", uploadedFile.getId());
		response.getWriter().write(fileReference);
	}
	@GetMapping(value = { "/listfiles" }, produces = { "application/json" })
	public @ResponseBody List<FileItemDTO> listFiles() throws Exception {
		Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred)
				.setApplicationName("DriveAPI").build();

		List<FileItemDTO> responseList = new ArrayList<>();

		FileList fileList = drive.files().list().setFields("files(id,name,thumbnailLink)").execute();
		for (File file : fileList.getFiles()) {
			FileItemDTO item = new FileItemDTO();
			item.setId(file.getId());
			item.setName(file.getName());
			item.setThumbnailLink(file.getThumbnailLink());
			responseList.add(item);
		}

		return responseList;
	}
	@GetMapping(value= {"/watchchanges"})
	public void watchchanges() throws Exception{
		

        // authorization
        GoogleCredential credential = GoogleCredential.getApplicationDefault()
                .createScoped(DriveScopes.all());

        boolean refreshed = credential.refreshToken();

        // set up the global Drive instance
        Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
        		.setApplicationName("DriveAPI")
                .build();

        Channel channel = new Channel();
        channel.setId(UUID.randomUUID().toString());
        channel.setType("web_hook");
        //my ip here
        channel.setAddress("http://192.168.29.220.nip.io:8090/");

        StartPageToken pageToken = drive.changes().getStartPageToken().execute();
        System.out.println(pageToken.getStartPageToken());
        Channel changesChannel = drive.changes().watch(pageToken.getStartPageToken(), channel).execute();
        System.out.println(changesChannel.getExpiration());

        return;
	}
	@PostMapping(value = { "/makepublic/{fileId}" }, produces = { "application/json" })
	public @ResponseBody Message makePublic(@PathVariable(name = "fileId") String fileId) throws Exception {
		Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred)
				.setApplicationName("DriveAPI").build();

		Permission permission = new Permission();
		permission.setType("anyone");
		permission.setRole("reader");

		drive.permissions().create(fileId, permission).execute();

		Message message = new Message();
		message.setMessage("Permission has been successfully granted.");
		return message;
	}
	@DeleteMapping(value = { "/deletefile/{fileId}" }, produces = "application/json")
	public @ResponseBody Message deleteFile(@PathVariable(name = "fileId") String fileId) throws Exception {
		Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred)
				.setApplicationName("DriveAPI").build();

		drive.files().delete(fileId).execute();

		Message message = new Message();
		message.setMessage("File has been deleted.");
		return message;
	}
	@GetMapping(value = { "/createfolder/{folderName}" }, produces = "application/json")
	public @ResponseBody Message createFolder(@PathVariable(name = "folderName") String folder) throws Exception {
		Credential cred = flow.loadCredential(USER_IDENTIFIER_KEY);

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, cred)
				.setApplicationName("DriveAPI").build();

		File file = new File();
		file.setName(folder);
		file.setMimeType("application/vnd.google-apps.folder");

		drive.files().create(file).execute();

		Message message = new Message();
		message.setMessage("Folder has been created successfully.");
		return message;
	}
	@GetMapping(value = { "/servicelistfiles" }, produces = { "application/json" })
	public @ResponseBody List<FileItemDTO> listFilesInServiceAccount() throws Exception {
		Credential cred = GoogleCredential.fromStream(serviceAccountKey.getInputStream());
		
		GoogleClientRequestInitializer keyInitializer = new CommonGoogleClientRequestInitializer();

		Drive drive = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, null).setHttpRequestInitializer(cred)
				.setGoogleClientRequestInitializer(keyInitializer).build();

		List<FileItemDTO> responseList = new ArrayList<>();

		FileList fileList = drive.files().list().setFields("files(id,name,thumbnailLink)").execute();
		for (File file : fileList.getFiles()) {
			FileItemDTO item = new FileItemDTO();
			item.setId(file.getId());
			item.setName(file.getName());
			item.setThumbnailLink(file.getThumbnailLink());
			responseList.add(item);
		}

		return responseList;
	}
	class Message {
		private String message;

		public String getMessage() {
			return message;
		}

		public void setMessage(String message) {
			this.message = message;
		}

	}
	 public static String fetchChanges(String savedStartPageToken) throws IOException {

	    GoogleCredentials credentials = GoogleCredentials.getApplicationDefault()
	        .createScoped(Arrays.asList(DriveScopes.DRIVE_FILE));
	    HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(
	        credentials);

	    // Build a new authorized API client service.
	    Drive service = new Drive.Builder(new NetHttpTransport(),
	        GsonFactory.getDefaultInstance(),
	        requestInitializer)
	        .setApplicationName("Drive samples")
	        .build();
	    try {
	      // Begin with our last saved start token for this user or the
	      // current token from getStartPageToken()
	      String pageToken = savedStartPageToken;
	      while (pageToken != null) {
	        ChangeList changes = service.changes().list(pageToken)
	            .execute();
	        for (com.google.api.services.drive.model.Change change : changes.getChanges()) {
	          // Process change
	          System.out.println("Change found for file: " + change.getFileId());
	        }
	        if (changes.getNewStartPageToken() != null) {
	          // Last page, save this token for the next polling interval
	          savedStartPageToken = changes.getNewStartPageToken();
	        }
	        pageToken = changes.getNextPageToken();
	      }

	      return savedStartPageToken;
	    } catch (GoogleJsonResponseException e) {
	      // TODO(developer) - handle error appropriately
	      System.err.println("Unable to fetch changes: " + e.getDetails());
	      throw e;
	    }
	  }
	 	
	 public static String fetchStartPageToken() throws IOException {
	      
	    GoogleCredentials credentials = GoogleCredentials.getApplicationDefault()
	        .createScoped(Arrays.asList(DriveScopes.DRIVE_FILE));
	    HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(
	        credentials);

	    Drive service = new Drive.Builder(new NetHttpTransport(),
	        GsonFactory.getDefaultInstance(),
	        requestInitializer)
	        .setApplicationName("Drive samples")
	        .build();
	    try {
	      StartPageToken response = service.changes()
	          .getStartPageToken().execute();
	      System.out.println("Start token: " + response.getStartPageToken());

	      return response.getStartPageToken();
	    } catch (GoogleJsonResponseException e) {
	      // TODO(developer) - handle error appropriately
	      System.err.println("Unable to fetch start page token: " + e.getDetails());
	      throw e;
	    }
	  }


	private void saveToken(String code) throws IOException {
		System.out.println("Inside saveToken");
		GoogleTokenResponse	response =flow.newTokenRequest(code).setRedirectUri(CALLBACK_URI).execute();
		flow.createAndStoreCredential(response, USER_IDENTIFIER_KEY);
	}
	
}