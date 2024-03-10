package com.springSecurityApp.springSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "FwcIfbLY32CSL8PoNdhDCFYUpLxRSlHcoH3S21lpXK2m0C5v/Xyr/G3Q1uTMmiVYs3fH2+LQJftuOnCYNJ8lO1/Q/2YFVg35tzcWiB9RABY9eIEbrpMmtAchE87Bm/NAW1iwz76pKkg7PGEW1nPD2VEZpVJXLHYu0/pUFYSz7okKBp1bhUZlBpcNoUGVBWEar1h7T77lf3jF3T1HNf/I+XbITXYRFVTbJVXfg1vPzEZ1uMoGAKdYAyerSHMNULvid835+e+pTwh5fC7BA19hxNft8xhEFZKZzTRFmSiGL12YncBHrX4Q0BtyHWAtLWasj9arY3WXt8wJnNkTNq6vK3A8qbu3olH+HnVw4Pbh/74=";

    public String extractUsername(String token) {
        //the subject of the token which is the email/username
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim (String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken (UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken (
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }
    
    public boolean isTokenValid (String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    
    private boolean isTokenExpired (String token) {
        return  extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
