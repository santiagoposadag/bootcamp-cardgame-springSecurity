package org.example.cardgame.application.command;

import com.google.gson.Gson;
import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;
import org.example.cardgame.generic.Command;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.EventPublisher;
import org.example.cardgame.generic.serialize.AbstractSerializer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.operation.OperationRequest;
import org.springframework.restdocs.operation.OperationResponse;
import org.springframework.restdocs.operation.OperationResponseFactory;
import org.springframework.restdocs.operation.preprocess.OperationPreprocessor;
import org.springframework.restdocs.payload.RequestFieldsSnippet;
import org.springframework.restdocs.restassured3.RestDocumentationFilter;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.lang.reflect.Type;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;
import static org.springframework.restdocs.restassured3.RestAssuredRestDocumentation.document;
import static org.springframework.restdocs.restassured3.RestAssuredRestDocumentation.documentationConfiguration;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = AppCommand.class)
@ExtendWith({RestDocumentationExtension.class, SpringExtension.class})
public class CommandBaseIntegrationTest {


    private RequestSpecification documentationSpec;


    @SpyBean
    private EventPublisher bus;

    @Captor
    private ArgumentCaptor<DomainEvent> eventArgumentCaptor;

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

    protected void executor(Command request, String path, RequestFieldsSnippet requestFieldsSnippet, int numEvents) {
        RestDocumentationFilter docs = getSpecDoc(numEvents, request.getClass().getSimpleName().toLowerCase(),
                requestFieldsSnippet
        );
        given(documentationSpec)
                .filter(docs)
                .contentType(ContentType.JSON)
                .body(new GsonCommandSerializer().serialize(request))
                .when()
                .post(path)
                .then()
                .assertThat().statusCode(is(200));

    }

    protected RestDocumentationFilter getSpecDoc(int numEvents, String name, RequestFieldsSnippet requestFieldsSnippet) {
        return document(name,
                preprocessRequest(prettyPrint()),
                preprocessResponse(new OperationPreprocessor() {
                    @Override
                    public OperationRequest preprocess(OperationRequest operationRequest) {
                        return operationRequest;
                    }

                    @Override
                    public OperationResponse preprocess(OperationResponse operationResponse) {
                        verify(bus, times(numEvents)).publish(eventArgumentCaptor.capture());
                        return new OperationResponseFactory().create(
                                200,
                                operationResponse.getHeaders(),
                                new Gson().toJson(eventArgumentCaptor.getAllValues()).getBytes()
                        );
                    }
                }, prettyPrint()),
                requestFieldsSnippet
        );
    }


    public final class GsonCommandSerializer extends AbstractSerializer  {

        public <T extends Command> T deserialize(String aSerialization, Class<?> aType) {
            return gson.fromJson(aSerialization, (Type) aType);
        }

        public String serialize(Command object) {
            return gson.toJson(object);
        }
    }
}