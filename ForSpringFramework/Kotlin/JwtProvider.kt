package 

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtProvider(private val customUserDetailsService: USER DETAIL SERVICE OR USER DATA INJECTING SERVICE) {

    private val logger = LoggerFactory.getLogger(JwtProvider::class.java)

    companion object {
        private const val ACCESS_TOKEN_KEY_STRING = "CUSTOM SECRET KEY"
        private const val REFRESH_TOKEN_KEY_STRING = "CUSTOM SECRET KEY"
        private const val ACCESS_TOKEN_EXPIRATION_TIME: Long = EXPIRATION TIME SETTING REQUIRED
        private const val REFRESH_TOKEN_EXPIRATION_TIME: Long = EXPIRATION TIME SETTING REQUIRED

        private const val ISSUER = "ISSUER - "
        private const val AUDIENCE = "AUDIENCE - "

        private val ACCESS_TOKEN_SECRET_KEY: SecretKey = Keys.hmacShaKeyFor(ACCESS_TOKEN_KEY_STRING.toByteArray())
        private val REFRESH_TOKEN_SECRET_KEY: SecretKey = Keys.hmacShaKeyFor(REFRESH_TOKEN_KEY_STRING.toByteArray())
    }


    /**
     * 액세스 토큰 생성
     *
     * 사용자 ID를 기반 으로 액세스 토큰을 생성
     *
     * Generate Access Token
     *
     * Generates an access token based on the user's ID.
     *
     * @param id The user ID for which the access token is to be generated.
     * @return [String] - Generated JWT access token.
     * @throws Exception If an error occurs during token generation.
     * @author hc
     * @since 24.01.05
     * @see [CustomUserDetailService.getUserObjectById]
     * @see [Jwts.builder]
     */
    fun generateAccessToken(id: String): String {
        val userObject = USER INFO INJECTED FROM SERVICE
        return Jwts.builder()
            .header()
                .type("JWT")
                .and()
            .claims()
                .id(id)
                .add("company", userObject.company)
                .add("roles", userObject.roles)
                .add("ver", "Version Info")
                .add("apkVer", "Version Info")
                .issuer(ISSUER)
                .audience()
                    .add(AUDIENCE)
                    .and()
                .issuedAt(Date())
                .expiration(Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
                .and()
            .signWith(ACCESS_TOKEN_SECRET_KEY)
            .compact()
    }


    /**
     * 리프레시 토큰 생성
     *
     * 사용자 ID를 기반 으로 리프레시 토큰을 생성
     *
     * Generate Refresh Token
     *
     * Generates a refresh token based on the user's ID.
     *
     * @param id The user ID for which the refresh token is to be generated.
     * @return [String] - Generated JWT refresh token.
     * @throws Exception If an error occurs during token generation.
     * @author hc
     * @since 24.01.05
     * @see [CustomUserDetailService.getUserObjectById]
     * @see [Jwts.builder]
     */
    fun generateRefreshToken(id: String): String {
        val userObject = USER INFO INJECTED FROM SERVICE
        return Jwts.builder()
            .header()
                .type("JWT-RefreshToken")
                .and()
            .claims()
                .id(id)
            .issuer(ISSUER)
            .audience()
            .add(AUDIENCE)
            .and()
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
            .and()
            .signWith(REFRESH_TOKEN_SECRET_KEY)
            .compact()
    }


    /**
     * 액세스 토큰 유효성 검증
     *
     * 제공된 액세스 토큰이 유효 한지 확인
     *
     * Validate Access Token
     *
     * Validates the provided access token for its authenticity and validity.
     *
     * @param token The JWT access token to be validated.
     * @return [Boolean] - True if the token is valid, false otherwise.
     * @throws JwtException If the token is expired or invalid.
     * @throws Exception If any other exception occurs during token validation.
     * @author hc
     * @since 24.01.05
     * @see [Jwts.parser]
     */
    fun validateAccessToken(token: String): Boolean {
        return try {
            Jwts.parser()
                .verifyWith(ACCESS_TOKEN_SECRET_KEY)
                .build()
                .parseSignedClaims(token)
            true
        } catch (e: ExpiredJwtException) {
            throw JwtException("Expired Token")
        } catch (e: JwtException) {
            throw JwtException("Jwt Exception")
        } catch (e: Exception) {
            throw Exception()
        }
    }


    /**
     * 리프레시 토큰 유효성 검증
     *
     * 제공된 리프레시 토큰이 유효 한지 확인
     *
     * Validate Refresh Token
     *
     * Validates the provided refresh token for its authenticity and validity.
     *
     * @param token The JWT refresh token to be validated.
     * @return [Boolean] - True if the token is valid, false otherwise.
     * @throws JwtException If the token is expired or invalid.
     * @throws Exception If any other exception occurs during token validation.
     * @author hc
     * @since 24.01.05
     * @see [Jwts.parser]
     */
    fun validateRefreshToken(token: String): Boolean {
        return try {
            Jwts.parser()
                .verifyWith(REFRESH_TOKEN_SECRET_KEY)
                .build()
                .parseSignedClaims(token)
            true
        } catch (e: ExpiredJwtException) {
            throw JwtException("Expired Token")
        } catch (e: JwtException) {
            throw JwtException("Jwt Exception")
        } catch (e: Exception) {
            throw Exception()
        }
    }


    /**
     * 액세스 토큰 만료 확인 (더 이상 사용되지 않음)
     *
     * 액세스 토큰이 만료 되었는지 확인
     *
     * Check if Access Token is Expired (Deprecated)
     *
     * Checks if the provided access token has expired.
     *
     * @param token The JWT access token to check for expiration.
     * @return [Boolean] - False if the token has expired, true otherwise.
     * @deprecated Use validateToken(token) instead.
     * @throws Exception If an error occurs during token parsing.
     * @author hc
     * @since Deprecated 24.01.05
     * @see [Jwts.parser]
     */
    @Deprecated(message = "Method No LongerUsed", replaceWith = ReplaceWith("validateToken(token)"))
    fun isAccessTokenExpired(token: String): Boolean {
        return try {
            Jwts.parser()
                .verifyWith(ACCESS_TOKEN_SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .payload
                .expiration
                .before(Date())
        } catch (e: ExpiredJwtException) {
            false
        }
    }


    /**
     * 리프레시 토큰 만료 확인 (더 이상 사용되지 않음)
     *
     * 리프레시 토큰이 만료 되었는지 확인
     *
     * Check if Refresh Token is Expired (Deprecated)
     *
     * Checks if the provided refresh token has expired.
     *
     * @param token The JWT refresh token to check for expiration.
     * @return [Boolean] - False if the token has expired, true otherwise.
     * @deprecated Use validateToken(token) instead.
     * @throws Exception If an error occurs during token parsing.
     * @author hc
     * @since 24.01.05
     * @see [Jwts.parser]
     */
    @Deprecated(message = "Method No LongerUsed", replaceWith = ReplaceWith("validateToken(token)"))
    fun isRefreshTokenExpired(token: String): Boolean {
        return try {
            Jwts.parser()
                .verifyWith(REFRESH_TOKEN_SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .payload
                .expiration
                .before(Date())
        } catch (e: ExpiredJwtException) {
            false
        }
    }


    /**
     * 액세스 토큰으로부터 페이로드 추출
     *
     * 제공된 액세스 토큰에서 페이로드를 추출
     *
     * Extract Payloads from Access Token
     *
     * Extracts the payload from the given access token.
     *
     * @param token The JWT access token.
     * @return [Claims] - Extracted payloads from the access token.
     * @throws Exception If an error occurs during token parsing.
     * @author hc
     * @since 24.01.05
     * @see [Jwts.parser]
     */
    fun extractPayloadsFromAccessToken(token: String): Claims {
        return Jwts.parser()
            .verifyWith(ACCESS_TOKEN_SECRET_KEY)
            .build()
            .parseSignedClaims(token)
            .payload
    }


    /**
     * 리프레시 토큰으로부터 페이로드 추출
     *
     * 제공된 리프레시 토큰에서 페이로드를 추출
     *
     * Extract Payloads from Refresh Token
     *
     * Extracts the payload from the given refresh token.
     *
     * @param token The JWT refresh token.
     * @return [Claims] - Extracted payloads from the refresh token.
     * @throws Exception If an error occurs during token parsing.
     * @author hc
     * @since 24.01.05
     * @see [Jwts.parser]
     */
    fun extractPayloadsFromRefreshToken(token: String): Claims {
        return Jwts.parser()
            .verifyWith(REFRESH_TOKEN_SECRET_KEY)
            .build()
            .parseSignedClaims(token)
            .payload
    }


    /**
     * HTTP 요청으로부터 액세스 토큰 추출
     *
     * HTTP 요청의 헤더에서 액세스 토큰을 추출
     *
     * Extract Access Token from HTTP Request
     *
     * Extracts the access token from the 'Authorization' header of the HTTP request.
     *
     * @param request HttpServletRequest from which to extract the access token.
     * @return [String]? - The extracted access token, or null if not present.
     * @throws Exception If an error occurs during token extraction.
     * @author hc
     * @since 24.01.05
     * @see [HttpServletRequest.getHeader]
     */
    fun extractAccessTokenFromHttpRequest(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader("Authorization")
        if (bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7)
        }
        return null
    }


    /**
     * HTTP 요청으로부터 리프레시 토큰 추출
     *
     * HTTP 요청의 헤더에서 리프레시 토큰을 추출
     *
     * Extract Refresh Token from HTTP Request
     *
     * Extracts the refresh token from the 'X-Refresh-Token' header of the HTTP request.
     *
     * @param request HttpServletRequest from which to extract the refresh token.
     * @return [String]? - The extracted refresh token, or null if not present.
     * @throws Exception If an error occurs during token extraction.
     * @author hc
     * @since 24.01.05
     * @see [HttpServletRequest.getHeader]
     */
    fun extractRefreshTokenFromHttpRequest(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader("X-Refresh-Token")
        if (bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7)
        }
        return null
    }


    /**
     * 액세스 토큰으로부터 인증 정보 추출
     *
     * 제공된 액세스 토큰에서 인증 정보를 추출
     *
     * Extract Authentication from Access Token
     *
     * Extracts authentication information from the provided access token.
     *
     * @param token The JWT access token.
     * @return [Authentication] - Extracted authentication information.
     * @throws Exception If an error occurs during authentication extraction.
     * @author hc
     * @since 24.01.05
     * @see [extractPayloadsFromAccessToken]
     * @see [CustomUserDetailsService.loadUserByUsername]
     */
    fun extractAuthenticationFromAccessToken(token: String): Authentication {
        val claims = this.extractPayloadsFromAccessToken(token)
        val roles: List<String> = claims["roles"] as List<String>
        return UsernamePasswordAuthenticationToken(
            customUserDetailsService.loadUserByUsername(claims),
            "Password Secured",
            roles.map { SimpleGrantedAuthority(it) }.toMutableList()
        )
    }


    /**
     * 리프레시 토큰으로부터 인증 정보 추출
     *
     * 제공된 리프레시 토큰에서 인증 정보를 추출
     *
     * Extract Authentication from Refresh Token
     *
     * Extracts authentication information from the provided refresh token.
     *
     * @param token The JWT refresh token.
     * @return [Authentication] - Extracted authentication information.
     * @throws Exception If an error occurs during authentication extraction.
     * @author hc
     * @since 24.01.05
     * @see [extractPayloadsFromRefreshToken]
     * @see [CustomUserDetailsService.loadUserByUsername]
     */
    fun extractAuthenticationFromRefreshToken(token: String): Authentication {
        val claims = this.extractPayloadsFromRefreshToken(token)
        val roles: List<String> = claims["roles"] as List<String>
        return UsernamePasswordAuthenticationToken(
            customUserDetailsService.loadUserByUsername(claims),
            "Password Secured",
            roles.map { SimpleGrantedAuthority(it) }.toMutableList()
        )
    }



}