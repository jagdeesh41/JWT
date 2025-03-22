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



![JWT Image](/images/jwt.png)
