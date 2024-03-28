package com.shopme.admin.security;

/*
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public UserDetailsService userDetailsService() {
		return new ShopmeUserDetailsService();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());
		
		return authProvider;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/states/list_by_country/**").hasAnyAuthority("Admin", "Salesperson")
			.antMatchers("/users/**", "/settings/**", "/countries/**", "/states/**").hasAuthority("Admin")
			.antMatchers("/categories/**", "/brands/**").hasAnyAuthority("Admin", "Editor")
			
			.antMatchers("/products/new", "/products/delete/**").hasAnyAuthority("Admin", "Editor")
			
			.antMatchers("/products/edit/**", "/products/save", "/products/check_unique")
				.hasAnyAuthority("Admin", "Editor", "Salesperson")
				
			.antMatchers("/products", "/products/", "/products/detail/**", "/products/page/**")
				.hasAnyAuthority("Admin", "Editor", "Salesperson", "Shipper")
				
			.antMatchers("/products/**").hasAnyAuthority("Admin", "Editor")
			
			.antMatchers("/orders", "/orders/", "/orders/page/**", "/orders/detail/**").hasAnyAuthority("Admin", "Salesperson", "Shipper")
			
			.antMatchers("/products/detail/**", "/customers/detail/**").hasAnyAuthority("Admin", "Editor", "Salesperson", "Assistant")

			.antMatchers("/customers/**", "/orders/**", "/get_shipping_cost", "/reports/**").hasAnyAuthority("Admin", "Salesperson")
			
			.antMatchers("/orders_shipper/update/**").hasAuthority("Shipper")
			
			.antMatchers("/reviews/**").hasAnyAuthority("Admin", "Assistant")
			
			.anyRequest().authenticated()
			.and()
			.formLogin()			
				.loginPage("/login")
				.usernameParameter("email")
				.permitAll()
			.and().logout().permitAll()
			.and()
				.rememberMe()
					.key("AbcDefgHijKlmnOpqrs_1234567890")
					.tokenValiditySeconds(7 * 24 * 60 * 60);
					;
			http.headers().frameOptions().sameOrigin();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/images/**", "/js/**", "/webjars/**");
	}

	
}

*/

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;



import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig  {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();

	}

	/*
	 @Bean 
	 public UserDetailsService ShomeUserDetailService() {
		 return new ShopmeUserDetailService(); 
		 } */
	 
/*	@Bean
	 public void configure(AuthenticationManagerBuilder auth) throws Exception {
	  
	  auth.userDetailsService(shomeUserDetailService())
	 .passwordEncoder(passwordEncoder());
	 
	 
	 auth.inMemoryAuthentication().withUser("raj").password(this.passwordEncoder()
	 .encode("12345")).roles("normal"); 
	 } */

	
	 @Bean
	    public InMemoryUserDetailsManager userDetailsService() {
	        UserDetails user = User.withDefaultPasswordEncoder()
	            .username("user")
	            .password("{noop}password")
	            .roles("USER")
	            .build();
	        return new InMemoryUserDetailsManager(user);
	    }
	 
  /* @Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((authz) -> {
			try {
				authz
				.anyRequest()
				.permitAll()
				.and()
				.formLogin()
				.loginPage("/login")
				.permitAll()
				.and()
				.logout()
			     .permitAll();
				;
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}).httpBasic(withDefaults());
		return http.build();
	} */
   
   @Bean
   public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
       http
           .authorizeRequests((authz) -> authz
               .anyRequest().permitAll()
           )
           .httpBasic(withDefaults());
       return http.build();
   }

}

