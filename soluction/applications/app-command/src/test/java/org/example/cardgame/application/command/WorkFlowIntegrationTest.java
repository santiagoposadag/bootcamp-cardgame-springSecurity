package org.example.cardgame.application.command;

import org.example.cardgame.domain.command.CrearJuegoCommand;
import org.junit.jupiter.api.*;

import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class WorkFlowIntegrationTest extends CommandBaseIntegrationTest{

    @BeforeAll
    public static void beforeAll() {
        //TODO: ids
    }

    @BeforeEach
    public void setUp() {
        //TODO: clean
    }

    @Test
    @Order(1)
    void crearJuego() {
        var command = new CrearJuegoCommand();
        command.setJuegoId("1");
        command.setMontoRequerido(200);
        command.setAlias("Andres");
        command.setJugadorPrincipalId("1");
        executor(command, "/juego/crear", requestFields(
                fieldWithPath("juegoId").description("ID del Juego"),
                fieldWithPath("jugadorPrincipalId").description("ID del Jugador Principal"),
                fieldWithPath("alias").description("El Alias del Jugador Principal"),
                fieldWithPath("montoRequerido").description("El monto requerido"),
                fieldWithPath("when").description("La fecha en la que se emite el comando").optional(),
                fieldWithPath("uuid").description("El identificador del comando").optional()

        ), 2);
    }




}