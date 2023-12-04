package com.allen.login.security.utils;

import com.allen.login.dto.LoginDto;
import com.allen.login.dto.SubjectDto;
import com.allen.login.dto.UserDto;
import com.allen.login.entity.User;
import com.allen.login.utils.Constants;
import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.util.Random;

@Component
public class JwtTokenUtil {
    @Autowired
    Gson gson;

    @Autowired
    JedisPool jedisPool;

    @Value("${redis.instance.key}")
    private String instanceKey;

    public String tokenGenerator(User user){
        LoginDto loginDto = LoginDto.builder()
                .id(user.getId())
                .name(user.getName())
                .password(user.getPassword())
                .build();
        Jedis jedis = jedisPool.getResource();
        long createdOn = System.currentTimeMillis()/1000;
        long expireAt = System.currentTimeMillis()/1000 + Constants.ACCESS_TOKEN_VALIDITY_SECONDS;
        SubjectDto subjectDto = SubjectDto.builder()
                .id(user.getId())
                .createdOn(createdOn)
                .validTill(expireAt)
                .build();
        String redisKey = generateRedisToken(user.getId());
        jedis.set(redisKey, subjectDto.toString());
        jedis.expireAt(redisKey,expireAt);
//        Claims claims = Jwts.claims().setSubject(gson.toJson(loginDto));
        Claims claims = Jwts.claims().setSubject(redisKey);
        jedis.close();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuer("https://www.wikipedia.org/")
                .signWith(SignatureAlgorithm.HS256,Constants.SIGNING_KEY)
                .compact();
    }

    public String createSalt(){
        StringBuilder str = new StringBuilder();
        Random rand = new Random();
        String avlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        while(str.length()<6){
            str.append(avlChars.charAt((int) (rand.nextFloat()*avlChars.length())));
        }
        return str.toString();
    }
    public String generateRedisToken(int id){
        String token = instanceKey + createSalt() + id;
        return token;
    }

    public String getRedisToken(String token){
        Claims claims = Jwts.parser().setSigningKey(Constants.SIGNING_KEY).parseClaimsJwt(token).getBody();
        String redisToken = claims.getSubject();
        return redisToken;
    }

//    public int getCurrentUserID(String token){
//        String redisToken = getRedisToken(token);
//    }

    public SubjectDto getSubject(String redisKey){
        Jedis jedis = jedisPool.getResource();
        String subjectDtoData = jedis.get(redisKey);
        SubjectDto subject = gson.fromJson(subjectDtoData,SubjectDto.class);
        return subject;
    }
}