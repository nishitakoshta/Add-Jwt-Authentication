# Add-Jwt-Authentication
- JWT work flow
  ![IMG_2585](https://github.com/nishitakoshta/Add-Jwt-Authentication/assets/110012128/0d1eda21-bbee-4bb4-8c77-16b7a5b464c1)
- To add jwt authentication we should have these dependency
  ```
  implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
  runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
  runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
  ```
- Create service package inside this service package create `impl/CustomUserDetails` class then implement `UserDetails`.

```
public class CustomUserDetails extends Users implements UserDetails {

    private final String username;
    private final String password;
    private final int userId;
    private final Integer role;
    private final String email;

    public CustomUserDetails(Users byUsername) {
        this.username = byUsername.getUsername();
        this.password= byUsername.getPassword();
        this.userId = byUsername.getUserId();
        this.role = byUsername.getRole();
        this.email = byUsername.getEmail();
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.toString()));
    }
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }
    @Override
    public int getUserId() {
        return userId;
    }
    @Override
    public Integer getRole() {
        return role;
    }
    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

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
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody();
    }
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public String extractEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }
    public  boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractEmail(token);
        return (userName.equals(userDetails.getUsername()));
    }
    public Integer extractUserRole(String token){
        return extractClaim(token, claims -> claims.get("role", Integer.class));
    }
}
```
- Create package called `constant` inside this create `ApiPathExclusion` class to declare swagger resources
```
@Getter
@AllArgsConstructor
public enum ApiPathExclusion {

    SWAGGER_RESOURCES("/swagger-resources/**"),
    SWAGGER_UI_HTML("swagger-ui.html"), WEBJARS("/webjars/**"), SWAGGER_UI("/swagger-ui/**"),
    SWAGGER_API_V3_DOCS("/v3/api-docs/**");

    private final String path;
}
```
- Create SecurityConfiguration class under the config package to whitelist the API
```
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthFilter jwtAuthFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/api/v1/users/register")
                                .permitAll()
                                .requestMatchers("/api/v1/users/login").permitAll()
                                .requestMatchers(Stream.of(ApiPathExclusion.values()).map(ApiPathExclusion::getPath)
                                        .toArray(String[]::new))
                                .permitAll()
                                .anyRequest()
                                .authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}
```
- To save encrepted password to the database, for which we will create class `ApplicationConfig` in the config package[we will add only bean method of passwordEncoder
```
@Bean
public PasswordEncoder passwordEncoder() {
  return new BCryptPasswordEncoder();
}
```
#### Steps to authenticate
- We need to validate out request (validate whether password & username is correct)
- Verify whether user present or not
```
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            Users user = userRepository.findByEmail(username).orElseThrow();
            return new CustomUserDetails(user);
        };
    }
```
- Which authenicationProvider --> DaoAuthenticationProvider (inject)
- We need to authenticate using authenticationManager injecting this authenticationProvider
```
@Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
```
```
@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
```
- Verify whether userName and password is correct => UserNamePasswordAuthenticationToken
- Verify Whether user present in db
- Generate token
- Return token
- This steps will be created in impl class
```
public JwtResponseDTO userLogin(AuthRequestDTO authRequestDTO) {
        String username = authRequestDTO.getEmail();
        String password = authRequestDTO.getPassword();
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
#### Implement the JwtAuthFilter 
- Create JwtAuthFilter class in config folder
```
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request,
                                    @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {
        //Verify whether request has authorization header and it has bearer in it
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String email;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
        }
        //Extract user from the token
        assert authHeader != null;
        //Verify whether user is present in db
        // Verify whether token is valid
        jwt = authHeader.substring(7);
        email = jwtService.extractEmail(jwt);
        if(email != null && SecurityContextHolder.getContext().getAuthentication() == null){
            //if valid set to security context holder
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
	filterChain.doFilter(request, response);
    }
    //Verify if it is whitelisted path and if yes don't do anything
    @Override
    protected boolean shouldNotFilter(@NotNull HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        return path.contains("/api/v1/users") || // Existing whitelist
                path.startsWith("/swagger-ui") ||  // Add Swagger UI paths
                path.startsWith("/v3/api-docs");
    }
}
```
- Login Method
```
public JwtResponseDTO userLogin(AuthRequestDTO authRequestDTO) {
        String username = authRequestDTO.getEmail();
        String password = authRequestDTO.getPassword();
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        var user = usersRepository.findByEmail(username).orElseThrow();
        // Retrieve UserDetails after successful authentication
        // Generate JWT token using JwtService
        String token = jwtService.generateToken(new CustomUserDetails(user));
        // Create JwtResponseDTO with the generated token
        return JwtResponseDTO.builder()
                .accessToken(token)
                .build();
    }
```
- Add JwtAuthFilter in `securityFilterChain`
```
.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
.authenticationProvider(authenticationProvider)
.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
```
