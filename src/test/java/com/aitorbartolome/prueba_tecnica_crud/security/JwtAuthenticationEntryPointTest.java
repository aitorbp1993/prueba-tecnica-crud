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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationEntryPoint Tests")
class JwtAuthenticationEntryPointTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

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
    @DisplayName("Commence Authentication Tests")
    class CommenceAuthenticationTests {

        @Test
        @DisplayName("Should set correct content type")
        void shouldSetCorrectContentType() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException("Bad credentials");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        }

        @Test
        @DisplayName("Should set 401 Unauthorized status code")
        void shouldSet401UnauthorizedStatusCode() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException("Bad credentials");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            verify(response).setStatus(401);
        }

        @Test
        @DisplayName("Should write JSON response to writer")
        void shouldWriteJsonResponseToWriter() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException("Bad credentials");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            printWriter.flush();
            String jsonResponse = stringWriter.toString();

            assertFalse(jsonResponse.isEmpty());
            assertTrue(jsonResponse.contains("\"status\":401"));
            assertTrue(jsonResponse.contains("\"error\":\"UNAUTHORIZED\""));
            assertTrue(jsonResponse.contains(ErrorCode.JWT_007.getCode()));
        }

        @Test
        @DisplayName("Should flush writer after writing response")
        void shouldFlushWriterAfterWritingResponse() throws IOException, ServletException {
            // Arrange
            PrintWriter mockWriter = mock(PrintWriter.class);
            when(response.getWriter()).thenReturn(mockWriter);

            AuthenticationException exception = new BadCredentialsException("Bad credentials");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            verify(mockWriter).write(anyString());
            verify(mockWriter).flush();
        }
    }

    @Nested
    @DisplayName("Different Authentication Exception Types Tests")
    class DifferentAuthenticationExceptionTypesTests {

        @Test
        @DisplayName("Should handle BadCredentialsException")
        void shouldHandleBadCredentialsException() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException("Invalid username or password");
            when(request.getRequestURI()).thenReturn("/api/v1/login");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            printWriter.flush();
            String jsonResponse = stringWriter.toString();
            assertFalse(jsonResponse.isEmpty());
        }

        @Test
        @DisplayName("Should handle generic AuthenticationException")
        void shouldHandleGenericAuthenticationException() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new AuthenticationException("Authentication failed") {};
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Integration Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle authentication exception with null message")
        void shouldHandleAuthenticationExceptionWithNullMessage() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException(null);
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act & Assert
            assertDoesNotThrow(() -> jwtAuthenticationEntryPoint.commence(request, response, exception));

            printWriter.flush();
            String jsonResponse = stringWriter.toString();
            assertFalse(jsonResponse.isEmpty());
        }

        @Test
        @DisplayName("Should handle authentication exception with empty message")
        void shouldHandleAuthenticationExceptionWithEmptyMessage() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException("");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act & Assert
            assertDoesNotThrow(() -> jwtAuthenticationEntryPoint.commence(request, response, exception));
        }

        @Test
        @DisplayName("Should handle multiple consecutive calls")
        void shouldHandleMultipleConsecutiveCalls() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception1 = new BadCredentialsException("First attempt");
            AuthenticationException exception2 = new BadCredentialsException("Second attempt");

            when(request.getRequestURI()).thenReturn("/api/v1/first", "/api/v1/second");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception1);

            // Reset for second call
            stringWriter = new StringWriter();
            printWriter = new PrintWriter(stringWriter);
            when(response.getWriter()).thenReturn(printWriter);

            jwtAuthenticationEntryPoint.commence(request, response, exception2);

            // Assert
            verify(response, times(2)).setContentType(MediaType.APPLICATION_JSON_VALUE);
            verify(response, times(2)).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        @Test
        @DisplayName("Should verify writer is called exactly once with correct JSON")
        void shouldVerifyWriterIsCalledExactlyOnceWithCorrectJson() throws IOException, ServletException {
            // Arrange
            PrintWriter mockWriter = mock(PrintWriter.class);
            when(response.getWriter()).thenReturn(mockWriter);

            AuthenticationException exception = new BadCredentialsException("Bad credentials");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            ArgumentCaptor<String> jsonCaptor = ArgumentCaptor.forClass(String.class);
            verify(mockWriter, times(1)).write(jsonCaptor.capture());
            verify(mockWriter, times(1)).flush();

            String capturedJson = jsonCaptor.getValue();
            assertTrue(capturedJson.contains("\"status\":401"));
            assertTrue(capturedJson.contains("\"error\":\"UNAUTHORIZED\""));
        }

        @Test
        @DisplayName("Should verify response status is exactly 401")
        void shouldVerifyResponseStatusIsExactly401() throws IOException, ServletException {
            // Arrange
            AuthenticationException exception = new BadCredentialsException("Bad credentials");
            when(request.getRequestURI()).thenReturn("/api/v1/test");

            // Act
            jwtAuthenticationEntryPoint.commence(request, response, exception);

            // Assert
            ArgumentCaptor<Integer> statusCaptor = ArgumentCaptor.forClass(Integer.class);
            verify(response).setStatus(statusCaptor.capture());
            assertEquals(401, statusCaptor.getValue());
        }
    }
}