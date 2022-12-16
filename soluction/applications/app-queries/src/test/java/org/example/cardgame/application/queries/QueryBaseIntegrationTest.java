package org.example.cardgame.application.queries;


import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.payload.RequestFieldsSnippet;
import org.springframework.restdocs.restassured3.RestDocumentationFilter;
import org.springframework.test.context.junit.jupiter.SpringExtension;


import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.restassured3.RestAssuredRestDocumentation.document;
import static org.springframework.restdocs.restassured3.RestAssuredRestDocumentation.documentationConfiguration;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = AppQuery.class)
@ExtendWith({RestDocumentationExtension.class, SpringExtension.class})
public class QueryBaseIntegrationTest {


    private RequestSpecification documentationSpec;

    @BeforeAll
    static void cleanAll() {
       // new MongoClient().getDatabase("queries").drop();
    }

    @BeforeEach
    public void setUp(RestDocumentationContextProvider restDocumentation) {
        this.documentationSpec = new RequestSpecBuilder()
                .addFilter(documentationConfiguration(restDocumentation))
                .build();

    }

    @LocalServerPort
    private void initRestAssured(final int localPort) {
        RestAssured.port = localPort;
        RestAssured.baseURI = "http://localhost";
    }

    protected Response executor(String path, RequestFieldsSnippet requestFieldsSnippet) {
        RestDocumentationFilter docs = getSpecDoc(path,requestFieldsSnippet);
        return given(documentationSpec)
                .filter(docs)
                .when()
                .contentType(ContentType.JSON)
                .get(path)
                .then()
                .assertThat().statusCode(is(200))
                .extract().response();

    }

    protected RestDocumentationFilter getSpecDoc(String name, RequestFieldsSnippet requestFieldsSnippet) {
        return document(name,
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint())
        );
    }
}