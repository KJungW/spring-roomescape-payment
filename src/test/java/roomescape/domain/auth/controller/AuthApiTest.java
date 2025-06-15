package roomescape.domain.auth.controller;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.headers.HeaderDocumentation.responseHeaders;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.document;
import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.documentationConfiguration;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.test.context.ActiveProfiles;
import roomescape.domain.auth.dto.AccessTokenContent;
import roomescape.domain.member.domain.Member;
import roomescape.domain.member.domain.Role;
import roomescape.domain.member.repository.MemberRepository;
import roomescape.utility.JwtTokenProvider;

@AutoConfigureRestDocs
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class AuthApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    public JwtTokenProvider tokenProvider;
    @Autowired
    private RestDocumentationContextProvider restDocumentation;

    @BeforeEach
    void setup() {
        RestAssured.filters(documentationConfiguration(restDocumentation));
    }

    @AfterEach
    void afterEach() {
        RestAssured.reset();
        memberRepository.deleteAll();
    }

    @Nested
    @DisplayName("로그인 할 수 있다.")
    public class login {

        @DisplayName("로그인 할 수 있다.")
        @Test
        void canLogin() {
            // given
            Member member = memberRepository.save(
                    Member.createWithoutId(Role.GENERAL, "회원", "member@email.com", "qwer1234!"));

            Map<String, Object> params = new HashMap<>();
            params.put("email", member.getEmail());
            params.put("password", member.getPassword());

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .filter(document(
                            "login",
                            requestFields(
                                    fieldWithPath("email").description("사용자 이메일"),
                                    fieldWithPath("password").description("사용자 비밀번호")
                            ),
                            responseHeaders(
                                    headerWithName("Set-Cookie").description("access 쿠키 : access 토큰이 담김")
                            )
                    ))
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value())
                    .cookie("access", notNullValue());
        }

        @DisplayName("이메일에 해당하는 계정이 존재하지 않는 경우 로그인할 수 없다.")
        @Test
        void cannotLoginByInvalidEmail() {
            // given
            Map<String, Object> params = new HashMap<>();
            params.put("email", "test@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .filter(document("login/duplicated_email"))
                    .when().post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.BAD_REQUEST.value());
        }

        @DisplayName("비밀번호가 맞지 않는 경우 로그인할 수 없다.")
        @Test
        void cannotLoginByInvalidPassword() {
            // given
            Member member = memberRepository.save(
                    Member.createWithoutId(Role.GENERAL, "회원", "member@email.com", "qwer1234!"));

            Map<String, Object> params = new HashMap<>();
            params.put("email", member.getEmail());
            params.put("password", "asdfg1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("login"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .filter(document("login/incorrect_password"))
                    .when().post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.BAD_REQUEST.value());
        }
    }

    @Nested
    @DisplayName("로그인 여부를 체크할 수 있다.")
    public class checkLogin {

        @DisplayName("엑세스 토큰이 존재할 경우 로그인으로 간주")
        @Test
        void isLogin() {
            // given
            AccessTokenContent tokenContent = new AccessTokenContent(1L, Role.GENERAL, "회원");
            String accessToken = tokenProvider.createAccessToken(tokenContent);

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .header("Cookie", "access=" + accessToken)
                    .filter(document(
                            "login_check",
                            requestHeaders(
                                    headerWithName("cookie").description("access 쿠키 : 인증을 위한 엑세스 토큰이 담김")
                            ),
                            responseFields(
                                    fieldWithPath("id").description("회원 ID"),
                                    fieldWithPath("roleName").description("회원 권한명"),
                                    fieldWithPath("name").description("회원 이름")
                            )
                    ))
                    .when().get("/login/check")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value())
                    .body("id", is(1));
        }

        @DisplayName("엑세스 토큰이 존재하지 않을 경우 로그인하지 않은 것으로 간주")
        @Test
        void isNotLoginByNotAccessToken() {
            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .filter(document("login_check/empty_access_token"))
                    .when().get("/login/check")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }

        @DisplayName("엑세스 토큰이 만료된 경우 로그인하지 않은 것으로 간주")
        @Test
        void isNotLoginByExpiredAccessToken() {
            // given
            tokenProvider = new JwtTokenProvider("test_secret_key_test_secret_key_test_secret_key_test_secret_key", 0);
            AccessTokenContent tokenContent = new AccessTokenContent(1L, Role.GENERAL, "회원");
            String expiredToken = tokenProvider.createAccessToken(tokenContent);

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .header("Cookie", "access=" + expiredToken)
                    .filter(document("login_check/expired_token"))
                    .when().get("/login/check")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());

        }

        @DisplayName("엑세스 토큰이 수정된 경우 로그인하지 않은 것으로 간주")
        @Test
        void isNotLoginByDamagedAccessToken() {
            // given
            AccessTokenContent tokenContent = new AccessTokenContent(1L, Role.GENERAL, "회원");
            String accessToken = tokenProvider.createAccessToken(tokenContent);
            String damagedAccessToken = accessToken + "damaged";

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .header("Cookie", "access=" + damagedAccessToken)
                    .filter(document("login_check/damaged_access_token"))
                    .when().get("/login/check")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }
    }

    @DisplayName("로그아웃할 수 있다.")
    @Test
    void canLogout() {
        // given
        AccessTokenContent tokenContent = new AccessTokenContent(1L, Role.GENERAL, "회원");
        String accessToken = tokenProvider.createAccessToken(tokenContent);

        // when & then
        RestAssured
                .given().log().all()
                .filter(document("logout"))
                .contentType(ContentType.JSON)
                .port(port)
                .cookie("access", accessToken)
                .when().post("/logout")
                .then().log().all()
                .statusCode(HttpStatus.OK.value())
                .cookie("access", is(""));
    }
}
