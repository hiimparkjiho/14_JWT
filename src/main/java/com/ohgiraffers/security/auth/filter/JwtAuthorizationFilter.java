package com.ohgiraffers.security.auth.filter;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.common.AuthConstants;
import com.ohgiraffers.security.common.utils.TokenUtils;
import com.ohgiraffers.security.user.entity.User;
import com.ohgiraffers.security.user.model.OhgirafferRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 권한이 필요없는 리소스
        List<String> roleLessList = Arrays.asList(
                "/signup"
        );

        // 권한이 필요 없는 요청이 들어왔는지 확인한다.
        if(roleLessList.contains(request.getRequestURI())){
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        try {
            // header가 존재하는 경우
            if(header != null && !header.equalsIgnoreCase("")){
                String token = TokenUtils.splitHeader(header);

                if(TokenUtils.isValidToken(token)){
                    Claims claims = TokenUtils.getClaimsFormToken(token);// 토큰을 복호화해서 클래임으로 받아옴
                    DetailsUser authentication = new DetailsUser(); // AbstractAuthenticationToken에 필요하기 위해 생성
                    User user = new User();
                    user.setUserName(claims.get("userId").toString());// 토큰에 넣어주기 위해

                    user.setRole(OhgirafferRole.valueOf(claims.get("Role").toString()));
                    authentication.setUser(user);   // 토큰에다가 유저 정보를 넣어준다.

                    AbstractAuthenticationToken authenticationToken =
                            UsernamePasswordAuthenticationToken.authenticated(authentication, token, authentication.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);  // security contextHolder에 토큰 객체를 넣어준다
                    chain.doFilter(request, response);// 다음 로직 실행
                }else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }
            } else{
                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        } catch (Exception e){
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonresponseWrapper(e);
            printWriter.println(jsonObject);
            printWriter.flush();
            printWriter.close();
        }
    }
    private JSONObject jsonresponseWrapper(Exception e){
        String resultMsg = "";
        if(e instanceof ExpiredJwtException){
            resultMsg = "Token Expired";
        }else if(e instanceof SignatureException){
            resultMsg = "Token signatureException login";
        }else if(e instanceof JwtException){
            resultMsg = "Token Parsing JwtException";
        }else{
            resultMsg = "Other token error";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;
    }
}
