package 

import com.kotlin.spring.management.configurations.security.jwt.JwtProvider
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.util.AntPathMatcher
import org.springframework.web.filter.OncePerRequestFilter

/**
 * JWT Filter For SpringFramework
 * Required Dependency
 * -JJWT
 * @author hc
 * @since 24.01.05
 *
 */
class JsonWebTokenFilter(
    private val jwtProvider: JwtProvider
): OncePerRequestFilter() {
    // Refresh Token Request URI
    private val REFRESH_REQUEST_PATH = "/api/jwt/refresh"

    private val logger = LoggerFactory.getLogger(JsonWebTokenFilter::class.java)
    private val pathMatcher = AntPathMatcher()


    /**
     * 내부 필터 처리
     *
     * HTTP 요청을 필터링하고, 적절한 토큰 처리 로직을 수행
     *
     * Internal Filter Processing
     *
     * Filters each HTTP request, handling refresh and access token verification, and proceeding with the filter chain if applicable.
     *
     * @param request HttpServletRequest to check for tokens and path matching.
     * @param response HttpServletResponse to return the processed response.
     * @param filterChain FilterChain to continue the filter process if the request passes all checks.
     * @return [Unit] - This function does not return a value but either continues the filter chain or handles the response directly.
     * @throws Exception If an error occurs during filter processing.
     * @author hc
     * @since 24.01.05
     * @see [isRefreshTokenRequest]
     * @see [handleRefreshTokenRequest]
     * @see [processJwtAuthentication]
     */
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        // Refresh Token
        if (isRefreshTokenRequest(request)) {
            handleRefreshTokenRequest(request, response)
            return
        }
        // Access Token
        if (pathMatcher.match("/api/**", request.servletPath) &&
            !pathMatcher.match("/api/login", request.servletPath) &&
            !pathMatcher.match("/api/user/register/register", request.servletPath)) {
            if (!processJwtAuthentication(request, response)) {
                return
            }
        }
        if (!response.isCommitted) {
            filterChain.doFilter(request, response)
        }
    }


    /**
     * AccessToken Verify
     *
     * Request로 부터 JsonWebToken을 추출하여 유효성을 검사
     *
     * Extract The Token From request and Verify The Token
     *
     * @param request HttpServletRequest For Token Extraction. Extract Token From 'Authorization' Header
     * @param response HttpServletResponse For Returning Http Responses When Exception Occurred
     * @return [Boolean] - JWT Token Validity. If The Token is Valid, It Returns True
     * @throws Exception Throws Multiple Exceptions Depending On Token Validity
     * @author hc
     * @since 24.01.05
     * @see [JwtProvider.extractAccessTokenFromHttpRequest]
     * @see [JwtProvider.validateAccessToken]
     */
    private fun processJwtAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): Boolean {
        try {
            logger.info("JwtFilterChain Activated - RequestURI[${request.servletPath}]")
            val token = jwtProvider.extractAccessTokenFromHttpRequest(request)
            if (SecurityContextHolder.getContext().authentication == null && token != null) {
                if (jwtProvider.validateAccessToken(token)) {
                    SecurityContextHolder.getContext().authentication = jwtProvider.extractAuthenticationFromAccessToken(token)
                    logger.info("Request Successful")
                    return true
                }
            } else if (token != null) {
                logger.info("Verifying Token...")
                return jwtProvider.validateAccessToken(token)
            } else {
                this.handleWhenNoToken(response)
            }
        } catch (e: ExpiredJwtException) {
            logger.info("ExpiredJwtException")
            this.handleTokenExpiredException(response, e)
        } catch (e: JwtException) {
            logger.info("JwtException")
            this.handleJwtException(response, e)
        } catch (e: AuthenticationException) {
            logger.info("AuthenticationException")
            this.handleAuthenticationException(response, e)
        } catch (e: Exception) {
            logger.info("Exception")
            this.handleMiscellaneousExceptions(response, e)
        }
        return false
    }


    /**
     * 토큰이 없을 때의 처리
     *
     * 토큰이 없는 경우 요청을 실패로 처리하고, 적절한 HTTP 응답을 반환
     *
     * Handle When There Is No Token
     *
     * Logs the absence of a token, responds with an HTTP 401 Unauthorized status, and returns a corresponding error message.
     *
     * @param response HttpServletResponse to send back an error response.
     * @return [Boolean] - Always returns false to indicate that no valid token was found.
     * @throws Exception If an error occurs while writing the response.
     * @author hc
     * @since 24.01.05
     */
    private fun handleWhenNoToken(response: HttpServletResponse): Boolean {
        logger.info("Request Failed - There Is No Token")
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.writer.write("{\"message\": \"Authorization error: There Is No Authorization Token.\"}")
        response.writer.flush()
        return false
    }


    /**
     * JWT 예외 처리
     *
     * JWT 예외 발생 시 요청을 실패로 처리하고, 적절한 HTTP 응답을 반환
     *
     * Handle JWT Exception
     *
     * Manages the handling of a JwtException during a request. Logs the failure and sends an unauthorized HTTP response.
     *
     * @param response HttpServletResponse to send back an error response.
     * @param exception JwtException that was thrown during token processing.
     * @return [Unit] - This function does not return a value but writes the response directly to the HttpServletResponse object.
     * @throws Exception If an error occurs while writing the response.
     * @author hc
     * @since 24.01.05
     */
    private fun handleJwtException(response: HttpServletResponse, exception: JwtException) {
        logger.info("Request Failed - JwtException")
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.writer.write("{\"message\": \"Authorization error: Invalid token.\"}")
        response.writer.flush()
    }


    /**
     * 인증 예외 처리
     *
     * 인증 예외 발생 시 요청을 실패로 처리하고, 적절한 HTTP 응답을 반환
     *
     * Handle Authentication Exception
     *
     * Handles an AuthenticationException during a request. Logs the failure and sends an unauthorized HTTP response.
     *
     * @param response HttpServletResponse to send back an error response.
     * @param exception AuthenticationException that was thrown during token processing.
     * @return [Unit] - This function does not return a value but writes the response directly to the HttpServletResponse object.
     * @throws Exception If an error occurs while writing the response.
     * @author hc
     * @since 24.01.05
     */
    private fun handleAuthenticationException(response: HttpServletResponse, exception: AuthenticationException) {
        logger.info("Request Failed - AuthenticationException")
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.writer.write("{\"message\": \"Authorization error: Invalid token.\"}")
        response.writer.flush()
    }


    /**
     * 토큰 만료 예외 처리
     *
     * 토큰 만료 예외 발생 시 요청을 실패로 처리하고, 적절한 HTTP 응답을 반환
     *
     * Handle Token Expired Exception
     *
     * Manages the handling of an ExpiredJwtException. Logs the failure and sends an unauthorized HTTP response.
     *
     * @param response HttpServletResponse to send back an error response.
     * @param exception ExpiredJwtException that was thrown due to an expired token.
     * @return [Unit] - This function does not return a value but writes the response directly to the HttpServletResponse object.
     * @throws Exception If an error occurs while writing the response.
     * @author hc
     * @since 24.01.05
     */
    private fun handleTokenExpiredException(response: HttpServletResponse, exception: ExpiredJwtException) {
        logger.info("Request Failed - ExpiredJwtException")
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.writer.write("{\"message\": \"Authorization error: Expired token.\"}")
        response.writer.flush()
    }


    /**
     * 기타 예외 처리
     *
     * 다양한 예외 발생 시 요청을 실패로 처리하고, 적절한 HTTP 응답을 반환
     *
     * Handle Miscellaneous Exceptions
     *
     * Handles miscellaneous exceptions during a request. Logs the failure and sends a bad request HTTP response.
     *
     * @param response HttpServletResponse to send back an error response.
     * @param exception Exception that was thrown during the process.
     * @return [Unit] - This function does not return a value but writes the response directly to the HttpServletResponse object.
     * @throws Exception If an error occurs while writing the response.
     * @author hc
     * @since 24.01.05
     */
    private fun handleMiscellaneousExceptions(response: HttpServletResponse, exception: Exception) {
        logger.info("Request Failed - MiscellaneousException")
        response.status = HttpServletResponse.SC_BAD_REQUEST
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.writer.write("{\"message\": \"Authorization error: Invalid token.\"}")
        response.writer.flush()
    }


    /**
     * 리프레시 토큰 요청 경로 확인
     *
     * 요청이 리프레시토큰 검증에 대한 요청 경로인지 확인
     *
     * Check if Request is for Refresh Token
     *
     * Determines whether the incoming HttpServletRequest is a request for a refresh token.
     *
     * @param request HttpServletRequest to be checked against the refresh token request path.
     * @return [Boolean] - True if the request is for a refresh token, false otherwise.
     * @author hc
     * @since 24.01.05
     */
    private fun isRefreshTokenRequest(request: HttpServletRequest): Boolean {
        return request.servletPath == REFRESH_REQUEST_PATH
    }


    /**
     * 리프레시 토큰 처리
     *
     * Refresh 토큰을 처리합니다. [isRefreshTokenRequest] 를 통하여 RefreshToken 관련 URL 일 경우, AccessToken을 재발급
     *
     * Handle Refresh Token Request
     *
     * *!Warning!* For Now, This Logic does not save The Token To DB, however Consider Saving Token To DB and improve the Security
     *
     * Processes the refresh token request, validates the refresh token, and issues a new access token.
     *
     * @param request HttpServletRequest to extract the refresh token. The refresh token is expected in the 'Authorization' header.
     * @param response HttpServletResponse to send back the new access token or an error message.
     * @return [Unit] - This function does not return a value but writes the response directly to the HttpServletResponse object.
     * @throws Exception If an error occurs during token extraction, validation, or access token generation.
     * @author hc
     * @since 24.01.05
     * @see [JwtProvider.extractRefreshTokenFromHttpRequest]
     * @see [JwtProvider.validateRefreshToken]
     * @see [JwtProvider.extractAuthenticationFromRefreshToken]
     * @see [JwtProvider.generateAccessToken]
     */
    private fun handleRefreshTokenRequest(
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val refreshToken = jwtProvider.extractRefreshTokenFromHttpRequest(request)
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        if (refreshToken != null && jwtProvider.validateRefreshToken(refreshToken)) {
            val authentication = jwtProvider.extractAuthenticationFromRefreshToken(refreshToken)
            val newAccessToken = jwtProvider.generateAccessToken(authentication.name)
            response.status = HttpServletResponse.SC_OK
            response.writer.write("{\"accessToken\": \"$newAccessToken\"}")
        } else {
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.writer.write("{\"error\": \"Invalid refresh token\"}")
        }
        response.writer.flush()
    }

}