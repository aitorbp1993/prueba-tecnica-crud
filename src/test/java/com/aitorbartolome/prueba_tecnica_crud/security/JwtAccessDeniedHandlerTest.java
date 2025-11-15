package com.aitorbartolome.prueba_tecnica_crud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorCode;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAccessDeniedHandler Tests")
class JwtAccessDeniedHandlerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    private StringWriter stringWriter;
    private PrintWriter printWriter;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() throws IOException {
        stringWriter = new StringWriter();
        printWriter = new PrintWriter(stringWriter);
        objectMapper = new ObjectMapper();

        when(response.getWriter()).thenReturn(printWriter);
    }

    @Nested
    @DisplayName("Handle Access Denied Tests")
    class HandleAccessDeniedTests {

        @Test
        @DisplayName("Should set correct content type")
        void shouldSetCorrectContentType() throws IOException, ServletException {
            // Arrange
            AccessDeniedException exception = new AccessDeniedException("Access denied");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAccessDeniedHandler.handle(request, response, exception);

            // Assert
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        @DisplayName("Should set 403 Forbidden status code")
        void shouldSet403ForbiddenStatusCode() throws IOException, ServletException {
            // Arrange
            AccessDeniedException exception = new AccessDeniedException("Access denied");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAccessDeniedHandler.handle(request, response, exception);

            // Assert
            verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
            verify(response).setStatus(403);
        }

        @Test
        @DisplayName("Should write JSON response to writer")
        void shouldWriteJsonResponseToWriter() throws IOException, ServletException {
            // Arrange
            AccessDeniedException exception = new AccessDeniedException("Access denied");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAccessDeniedHandler.handle(request, response, exception);

            // Assert
            printWriter.flush();
            String jsonResponse = stringWriter.toString();

            assertFalse(jsonResponse.isEmpty());
            assertTrue(jsonResponse.contains("\"status\":403"));
            assertTrue(jsonResponse.contains("\"error\":\"FORBIDDEN\""));
            assertTrue(jsonResponse.contains(ErrorCode.AUTHZ_001.getCode()));
        }

        @Test
        @DisplayName("Should flush writer after writing response")
        void shouldFlushWriterAfterWritingResponse() throws IOException, ServletException {
            // Arrange
            PrintWriter mockWriter = mock(PrintWriter.class);
            when(response.getWriter()).thenReturn(mockWriter);

            AccessDeniedException exception = new AccessDeniedException("Access denied");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAccessDeniedHandler.handle(request, response, exception);

            // Assert
            verify(mockWriter).write(anyString());
            verify(mockWriter).flush();
        }
    }

    @Nested
    @DisplayName("Edge Cases and Integration Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle access denied with null exception message")
        void shouldHandleAccessDeniedWithNullExceptionMessage() throws IOException, ServletException {
            // Arrange
            AccessDeniedException exception = new AccessDeniedException(null);
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act & Assert
            assertDoesNotThrow(() -> jwtAccessDeniedHandler.handle(request, response, exception));

            printWriter.flush();
            String jsonResponse = stringWriter.toString();
            assertFalse(jsonResponse.isEmpty());
        }

        @Test
        @DisplayName("Should handle access denied with empty exception message")
        void shouldHandleAccessDeniedWithEmptyExceptionMessage() throws IOException, ServletException {
            // Arrange
            AccessDeniedException exception = new AccessDeniedException("");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act & Assert
            assertDoesNotThrow(() -> jwtAccessDeniedHandler.handle(request, response, exception));
        }

        @Test
        @DisplayName("Should handle multiple consecutive calls")
        void shouldHandleMultipleConsecutiveCalls() throws IOException, ServletException {
            // Arrange
            AccessDeniedException exception1 = new AccessDeniedException("First access denied");
            AccessDeniedException exception2 = new AccessDeniedException("Second access denied");

            when(request.getRequestURI()).thenReturn("/api/v1/first", "/api/v1/second");

            // Act
            jwtAccessDeniedHandler.handle(request, response, exception1);

            // Reset for second call
            stringWriter = new StringWriter();
            printWriter = new PrintWriter(stringWriter);
            when(response.getWriter()).thenReturn(printWriter);

            jwtAccessDeniedHandler.handle(request, response, exception2);

            // Assert
            verify(response, times(2)).setContentType(MediaType.APPLICATION_JSON_VALUE);
            verify(response, times(2)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        }

        @Test
        @DisplayName("Should verify writer is called exactly once with correct JSON")
        void shouldVerifyWriterIsCalledExactlyOnceWithCorrectJson() throws IOException, ServletException {
            // Arrange
            PrintWriter mockWriter = mock(PrintWriter.class);
            when(response.getWriter()).thenReturn(mockWriter);

            AccessDeniedException exception = new AccessDeniedException("Access denied");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAccessDeniedHandler.handle(request, response, exception);

            // Assert
            ArgumentCaptor<String> jsonCaptor = ArgumentCaptor.forClass(String.class);
            verify(mockWriter, times(1)).write(jsonCaptor.capture());
            verify(mockWriter, times(1)).flush();

            String capturedJson = jsonCaptor.getValue();
            assertTrue(capturedJson.contains("\"status\":403"));
            assertTrue(capturedJson.contains("\"error\":\"FORBIDDEN\""));
        }
    }
}