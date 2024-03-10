package com.springSecurityApp.springSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;

@Service
public class JwtService {

    private static final String SECRET_KEY = "FwcIfbLY32CSL8PoNdhDCFYUpLxRSlHcoH3S21lpXK2m0C5v/Xyr/G3Q1uTMmiVYs3fH2+LQJftuOnCYNJ8lO1/Q/2YFVg35tzcWiB9RABY9eIEbrpMmtAchE87Bm/NAW1iwz76pKkg7PGEW1nPD2VEZpVJXLHYu0/pUFYSz7okKBp1bhUZlBpcNoUGVBWEar1h7T77lf3jF3T1HNf/I+XbITXYRFVTbJVXfg1vPzEZ1uMoGAKdYAyerSHMNULvid835+e+pTwh5fC7BA19hxNft8xhEFZKZzTRFmSiGL12YncBHrX4Q0BtyHWAtLWasj9arY3WXt8wJnNkTNq6vK3A8qbu3olH+HnVw4Pbh/74=\n"

    public String extractUsername(String token) {
        return null;
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
