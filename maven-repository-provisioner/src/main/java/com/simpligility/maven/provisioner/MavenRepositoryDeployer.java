/** 
 * Copyright simpligility technologies inc. http://www.simpligility.com
 * Licensed under Eclipse Public License - v 1.0 http://www.eclipse.org/legal/epl-v10.html
 */
package com.simpligility.maven.provisioner;

import static java.util.Arrays.asList;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.services.codeartifact.AWSCodeArtifact;
import com.amazonaws.services.codeartifact.AWSCodeArtifactClientBuilder;
import com.amazonaws.services.codeartifact.model.AssociateExternalConnectionRequest;
import com.amazonaws.services.codeartifact.model.ListPackageVersionAssetsRequest;
import com.amazonaws.services.codeartifact.model.ListPackageVersionAssetsResult;
import com.amazonaws.services.codeartifact.model.ListPackageVersionsRequest;
import com.amazonaws.services.codeartifact.model.ListPackageVersionsResult;
import com.simpligility.maven.Gav;
import com.simpligility.maven.GavUtil;
import com.simpligility.maven.MavenConstants;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.AndFileFilter;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.NotFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.deployment.DeployRequest;
import org.eclipse.aether.deployment.DeployResult;
import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.util.repository.AuthenticationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MavenRepositoryDeployer
{
    private static final Logger logger = LoggerFactory.getLogger( "MavenRepositoryHelper" );

    private final File repositoryPath;

    private RepositorySystem system;

    private DefaultRepositorySystemSession session;

    private final TreeSet<String> successfulDeploys = new TreeSet<>();

    private final TreeSet<String> failedDeploys = new TreeSet<>();

    private final TreeSet<String> skippedDeploys = new TreeSet<>();
    
    private final TreeSet<String> potentialDeploys = new TreeSet<>();
    private AWSCodeArtifact aws;
    public static final String CODE_ARTIFACT_DOMAIN = System.getenv("CODE_ARTIFACT_DOMAIN");
    public static final String CODE_ARTIFACT_REPO = System.getenv("CODE_ARTIFACT_REPO");
    public static final String AWS_REGION = System.getenv("AWS_REGION");
    public static final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");

    public MavenRepositoryDeployer( File repositoryPath )
    {
        this.repositoryPath = repositoryPath;
        initialize();
    }
    
    private void initialize()
    {
        system = RepositoryHandler.getRepositorySystem();
        session = RepositoryHandler.getRepositorySystemSession( system, repositoryPath );
        logger.info("AWS_REGION={}", AWS_REGION);
        logger.info("AWS_ACCESS_KEY_ID={}", AWS_ACCESS_KEY_ID);
        aws = AWSCodeArtifactClientBuilder.standard()
                .withCredentials(new EnvironmentVariableCredentialsProvider())
                .withRegion(AWS_REGION).build();

    }

    /**
     * Determine if it is a leaf directory with artifacts in it. Criteria used is that there is no subdirectory.
     * 
     * @param subDirectory
     * @return
     */
    private static boolean isLeafVersionDirectory( File subDirectory )
    {
        // it finds at least itself so have to check for > 1
        return FileUtils.listFilesAndDirs( subDirectory,
                VisibleDirectoryFileFilter.DIRECTORY,
                VisibleDirectoryFileFilter.DIRECTORY).size() <= 1;
    }
    
    public static Collection<File> getPomFiles( File repoPath )
    {
        try {
            return Files.walk(repoPath.toPath())
                    .map(Path::toFile)
                    .filter(f -> f.isFile() && f.getName().endsWith(".pom"))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public void deployToRemote( String targetUrl, String username, String password, boolean checkTarget,
        boolean verifyOnly )
    {

        try {
            Files.walk(repositoryPath.toPath())
                    .map(Path::toFile)
                    .filter(f -> f.isFile() && f.getName().endsWith(".pom"))
                    .map(File::getParentFile)
                    .limit(3)
                    .forEach(leafDirectory -> {
                        logger.info("Handling directory {}", leafDirectory.getAbsolutePath());
                        String leafAbsolutePath = leafDirectory.getAbsoluteFile().toString();
                        int repoAbsolutePathLength = repositoryPath.getAbsoluteFile().toString().length();
                        String leafRepoPath = leafAbsolutePath.substring(repoAbsolutePathLength + 1);

                        Gav gav = GavUtil.getGavFromRepositoryPath(leafRepoPath);

                        boolean pomInTarget = false;
                        if (checkTarget) {
                            pomInTarget = checkIfPomInTarget(targetUrl, username, password, gav);
                        }

                        if (pomInTarget) {
                            logger.info("Found POM for {} already in target. Skipping deployment.", gav);
                            skippedDeploys.add(gav.toString());
                        } else {
                            logger.info("Will deploy {}", gav);
                            // only interested in files using the artifactId-version* pattern
                            // don't bother with .sha1 files
                            IOFileFilter fileFilter =
                                    new AndFileFilter(asList(new WildcardFileFilter(gav.getArtifactId() + "-" + gav.getVersion() + "*"),
                                            new NotFileFilter(new SuffixFileFilter("sha1")),new NotFileFilter(new SuffixFileFilter("md5"))));
                            Collection<File> artifacts = FileUtils.listFiles(leafDirectory, fileFilter, null);

                            Authentication auth = new AuthenticationBuilder().addUsername(username).addPassword(password)
                                    .build();

                            RemoteRepository distRepo = new RemoteRepository.Builder("repositoryIdentifier", "default", targetUrl)
                                    .setProxy(ProxyHelper.getProxy(targetUrl))
                                    .setAuthentication(auth).build();

                            DeployRequest deployRequest = new DeployRequest();
                            deployRequest.setRepository(distRepo);
                            for (File file : artifacts) {
                                String extension;
                                if (file.getName().endsWith("tar.gz")) {
                                    extension = "tar.gz";
                                } else {
                                    extension = FilenameUtils.getExtension(file.getName());
                                }

                                String baseFileName = gav.getFilenameStart() + "." + extension;
                                String fileName = file.getName();
                                String g = gav.getGroupId();
                                String a = gav.getArtifactId();
                                String v = gav.getVersion();

                                Artifact artifact;
                                if (gav.getPomFilename().equals(fileName)) {
                                    artifact = new DefaultArtifact(g, a, MavenConstants.POM, v);
                                } else if (gav.getJarFilename().equals(fileName)) {
                                    artifact = new DefaultArtifact(g, a, MavenConstants.JAR, v);
                                } else if (gav.getSourceFilename().equals(fileName)) {
                                    artifact = new DefaultArtifact(g, a, MavenConstants.SOURCES, MavenConstants.JAR, v);
                                } else if (gav.getJavadocFilename().equals(fileName)) {
                                    artifact = new DefaultArtifact(g, a, MavenConstants.JAVADOC, MavenConstants.JAR, v);
                                } else if (baseFileName.equals(fileName)) {
                                    artifact = new DefaultArtifact(g, a, extension, v);
                                } else {
                                    String classifier =
                                            file.getName().substring(gav.getFilenameStart().length() + 1,
                                                    file.getName().length() - ("." + extension).length());
                                    artifact = new DefaultArtifact(g, a, classifier, extension, v);
                                }

                                artifact = artifact.setFile(file);
                                deployRequest.addArtifact(artifact);
                            }

                            try {
                                if (verifyOnly) {
                                    for (Artifact artifact : deployRequest.getArtifacts()) {
                                        potentialDeploys.add(artifact.toString());
                                    }
                                } else {
                                    DeployResult deploy = system.deploy(session, deployRequest);

                                    ListPackageVersionAssetsResult uploadedAssets = aws.listPackageVersionAssets(
                                            new ListPackageVersionAssetsRequest()
                                                    .withPackageVersion(gav.getVersion())
                                                    .withNamespace(gav.getGroupId()).withPackage(gav.getArtifactId()).withFormat("maven")
                                                    .withDomain(CODE_ARTIFACT_DOMAIN).withRepository(CODE_ARTIFACT_REPO)
                                    );
                                    uploadedAssets.getAssets().forEach(asset->{
                                        String md5 = asset.getHashes().get("MD5");
                                        failedDeploys.add(asset.getName() + " -> MD5=" + md5);
                                    });

                                    for (Artifact artifact : deployRequest.getArtifacts()) {
                                        successfulDeploys.add(artifact.toString());
                                    }
                                }
                            } catch (Exception e) {
                                logger.info("Deployment failed with {}, artifact might be deployed already.", e.getMessage());
                                for (Artifact artifact : deployRequest.getArtifacts()) {
                                    failedDeploys.add(artifact.toString());
                                }
                            }
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Check if POM file for provided gav can be found in target. Just does
     * a HTTP get of the header and verifies http status OK 200.
     * @param targetUrl url of the target repository
     * @param gav group artifact version string
     * @return {@code true} if the pom.xml already exists in the target repository
     */
    private boolean checkIfPomInTarget( String targetUrl, String username, String password, Gav gav )
    {
        boolean alreadyInTarget = false;
        
        String artifactUrl = targetUrl + gav.getRepositoryURLPath() + gav.getPomFilename();
        logger.debug( "Headers for {}", artifactUrl );

        HttpHead httphead = new HttpHead( artifactUrl );

        if ( !StringUtils.isEmpty( username ) && ! StringUtils.isEmpty( password ) )
        {
          String encoding = java.util.Base64.getEncoder().encodeToString( ( username + ":" + password ).getBytes() );
          httphead.setHeader( "Authorization", "Basic " + encoding );
        }

        try ( CloseableHttpClient httpClient = HttpClientBuilder.create().build() )
        {
          HttpResponse response = httpClient.execute( httphead );
          int statusCode = response.getStatusLine().getStatusCode();
          if ( statusCode == HttpURLConnection.HTTP_OK )
          {
              alreadyInTarget = true;
          }
          else
          {
              logger.debug( "Headers not found HTTP: {}", statusCode );
          }
        } 
        catch ( IOException ioe )
        {
          logger.warn( "Could not check target repository for already existing pom.xml.", ioe );
        }
        return alreadyInTarget;
    }


    public String listSucessfulDeployments()
    {
        StringBuilder builder = new StringBuilder();
        builder.append( "Sucessful Deployments:\n\n" );
        for ( String artifact : successfulDeploys )
        {
            builder.append(artifact).append("\n");
        }
        return builder.toString();
    }

    public String listFailedDeployments()
    {
        StringBuilder builder = new StringBuilder();
        builder.append( "Failed Deployments:\n\n" );
        for ( String artifact : failedDeploys )
        {
            builder.append(artifact).append("\n");
        }

        return builder.toString();
    }
    
    public String listSkippedDeployment()
    {
        StringBuilder builder = new StringBuilder();
        builder.append( "Skipped Deployments (POM already in target):\n\n" );
        for ( String artifact : skippedDeploys )
        {
            builder.append(artifact).append("\n");
        }

        return builder.toString();
    }

    public String listPotentialDeployment()
    {
        StringBuilder builder = new StringBuilder();
        builder.append( "Potential Deployments :\n\n" );
        for ( String artifact : potentialDeploys )
        {
            builder.append(artifact).append("\n");
        }

        return builder.toString();
    }

    public static Gav getCoordinates ( File pomFile ) throws Exception
    {
        BufferedReader in = new BufferedReader( new FileReader( pomFile ) );
        MavenXpp3Reader reader = new MavenXpp3Reader();
        Model model = reader.read( in );
        // get coordinates and take care of inheritance and default
        String g = model.getGroupId();
        if ( StringUtils.isEmpty( g ) ) 
        {
            g = model.getParent().getGroupId();
        }
        String a = model.getArtifactId();
        if ( StringUtils.isEmpty( a ) ) 
        {
            a = model.getParent().getArtifactId();
        }
        String v = model.getVersion();
        if ( StringUtils.isEmpty( v ) ) 
        {
            v = model.getParent().getVersion();
        }
        String p = model.getPackaging();
        if ( StringUtils.isEmpty( p ) ) 
        {
            p = MavenConstants.JAR;
        }
        return new Gav( g, a, v, p );
    }

    public boolean hasFailure() 
    {
      return !failedDeploys.isEmpty();
    }

    public String getFailureMessage() 
    {
      return "Failed to deploy some artifacts.";
    }
}
