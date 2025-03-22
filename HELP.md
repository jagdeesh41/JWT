# SPRING SECURITY
Look for this class where you find the SpringBootWebSecurityConfiguration
In SpringBootWebSecurityConfiguration.class we find the code related to security filter

    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception 
    {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }

InMemoryUserDetailsManager -> Non-persistent implementation of UserDetailsManager which is backed by an in-memory map.
UserDetails -> Provides core user information.

    @Bean
    UserDetailsService inMem()
    {
        UserDetails userDetails = 
        User.builder().username("user").password("{noop}password").roles("USER").build();
        UserDetails adminDetails = 
        User.builder().username("admin").password("{noop}password").roles("ADMIN").build();
        return new InMemoryUserDetailsManager(userDetails,adminDetails);
    }

    @Bean
    UserDetailsService inDb()
    {
        UserDetails userDetails = 
        User.builder().username("user2").password("{noop}password2").roles("USER").build();
        UserDetails adminDetails = 
        User.builder().username("admin2").password("{noop}password2").roles("ADMIN").build();
        UserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(userDetails);
        userDetailsManager.createUser(adminDetails);
        return userDetailsManager;
    }

Bcrypt involves using salting , which increases security 



![JWT_Image](/images/jwt.png)

![JWT_Structure](/images/jwt_str.png)

Understanding implementation of JWT 

![JWT_FilesInvolved](/images/jwt_files.png)

Let's talk about each file and know the importance of each

# JwtUtils
 --> Contains utility methods for generating, parsing and validating JWT.
 --> Include generating a token from username, validating a JWT, and extracting the username from a token 

# AuthTokenFilter
 --> we will write our own custom filter to intercept the request and do validation with the help of JwtUtils
 --> Filters incoming requests to check for a valid JWT in the header 
    setting the authentication context if the token is valid

# AuthEntryPointJwt
 --> Provides custom handling for unauthorized requests, 
    typically when authentication is required but not supplied or valid 
 --> when an unauthorized request is detected , it logs the error and return 
    a JSON response with an error message, status code, and the path attempted



