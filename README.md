# Add-Jwt-Authentication
- JWT work flow
  ![IMG_2585](https://github.com/nishitakoshta/Add-Jwt-Authentication/assets/110012128/0d1eda21-bbee-4bb4-8c77-16b7a5b464c1)
- To add jwt authentication we should have these dependency
  ```
  implementation 'io.jsonwebtoken:jjwt-api:0.12.5'
	runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.5'
	runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.5'
  ```
- Create config package inside this create `JwtService` class
```
@Service
public class JwtService {
    private static final String SECRET = "cfdde95671faf4db502743d2f080a6c83ebed73a696d395c3f9bdd9b1900fee6";
    public String createToken(Map<String, Object> claims){
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    private Key getSigningKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("userId", getUserIdFromUserDetails(userDetails));
        claims.put("userName", userDetails.getUsername());
        claims.put("role", getRoleFromUserDetails(userDetails));
        claims.put("emailId", getEmailIdFromUserDetails(userDetails));
        claims.put("authorities", populateAuthorities(userDetails.getAuthorities()));
        return createToken(claims);
    }
    private Integer getUserIdFromUserDetails(UserDetails userDetails) {
        return ((CustomUserDetails) userDetails).getUserId();
    }
    private RoleEnum getRoleFromUserDetails(UserDetails userDetails) {
        return RoleEnum.values()[((CustomUserDetails) userDetails).getRole()];
    }
    private String getEmailIdFromUserDetails(UserDetails userDetails) {
        return ((CustomUserDetails) userDetails).getEmail();
    }
    private String populateAuthorities(Collection<? extends GrantedAuthority> authorities){
        Set<String> authoritiesSet = new HashSet<>();
        for(GrantedAuthority authority: authorities){
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",",authoritiesSet);
    }
}
```
- Create SecurityConfiguration class under the config package to whitelist the API
```
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/api/v1/users/register")
                                .permitAll()
                                .requestMatchers("/api/v1/users/login").permitAll()
                                .requestMatchers("/swagger-ui/index.html")
                                .permitAll()
                                .anyRequest()
                                .authenticated())
                .build();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```
- Method for userLogin
```
public JwtResponseDTO userLogin(AuthRequestDTO authRequestDTO) {
        String username = authRequestDTO.getUsername();
        String password = authRequestDTO.getPassword();
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Username or password is empty");
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        // Retrieve UserDetails after successful authentication
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        // Generate JWT token using JwtService
        String token = jwtService.generateToken(userDetails);
        // Create JwtResponseDTO with the generated token
        return JwtResponseDTO.builder()
                .accessToken(token)
                .build();
    }
```
