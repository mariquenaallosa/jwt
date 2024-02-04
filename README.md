
# Spring Security - JWT - Roles de usuario - CORS

Objetivos : 
- Implementar *__Spring Security__* 
- Login y Registro con *__JWT__*
- Endpoints por __*ROL*__
- Configuración de *__CORS__*

## Autenticación con Json Web Token 
Al loguearse el usuario, si las credenciales (usuario y contraseña) son válidas, le enviará al front un JWT.
El front almacenará ese JWT, y lo incluirá en las posteriores requests para acceder a los endpoints protegidos.

El JWT contiene:

- HEADER: tipo de token y algoritmo de firma utilizado
- PAYLOAD: id usuario, roles, permisos. Se le pueden agregar más datos
- SIGNATURE: para garantizar que no haya sido manipulado




## Crear proyecto 

Dirigirse a [Spring Initializer](https://start.spring.io/) y agregar las dependencias que se ven a continuación

Lombok es una librería de anotaciones que nos ahorran código de getters, setters y contructores mientras que Validation nos facilita anotaciones para validar atributos como pueden ser @NotNull o @NotBlank.
Luego que descargamos el archivo generadom en el archivo pom.xml hay que agregar manualmente las 3 dependencias de JWT. 

```bash
        <dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.11.5</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
```
## AuthController

En esta clase están los endpoints para autenticación (Login y Registro). Estos métodos no estarán protegidos (se podrán acceder por un usuario no autenticado). Ambos devolverán un JWT. 
 

```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    
    @PostMapping("login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginDto datos) {
    	try {
    		return ResponseEntity.ok(authService.login(datos));
        } catch (RuntimeException e) {
            return new ResponseEntity(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("registro")
    public ResponseEntity<AuthResponse> registro(@RequestBody RegistroDto datos) {
    	try {
    		return ResponseEntity.ok(authService.registro(datos));
        } catch (RuntimeException e) {
            return new ResponseEntity(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

}
```


## DTO
Creamos las clases **LoginDto** y **RegistroDto** que habiamos indicado como parámetros en los endpoints Login y Registro.
También **AuthResponse**, la respuesta que retornarán esos endpoints: el JWT como String.

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegistroDto {
    String email;
    String password;
    String nombre;
    String apellido;
    String pais; 
    String rol;
}
```


```java
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {
    String email;
    String password; 
}
```

```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    String token; 
}
```

## Implementar UserDetails en tu Entidad Usuario
- UserDetails es un usuario de Spring Security. Es una interfaz, y debes implementarla en la entidad que será el usuario de tu app (User, Usuario, Persona, etc.). Al hacerlo, tu IDE te pedirá sobreescribir sus métodos.
- UserDetails tiene como atributos **username** y **password**. Aquí sobreescribimos el método getUsername y le indicamos que usaremos el email como username.
- En este caso no hizo falta sobreescribir el método getPassword porque ya tenemos un atributo "password" en la entidad User, y Lombok se está encargando de crear el getter por la anotación @Data.
- Le agregamos como atributo el Rol. **Los roles estarán listados en una Clase Enumerador** .
- En el método getAuthorities le pasamos el rol, serán los permisos que tiene ese usuario.
- A los métodos de expiración le ponemos todo true. No los usaremos, ya que eso se manejará con el JWT.


```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer id;
    String email;
    String apellido;
    String nombre;
    String pais;
    String password;
    
    @Enumerated(EnumType.STRING) 
    Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      return List.of(new SimpleGrantedAuthority((role.name())));
    }
    @Override
    public String getUsername() {
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

```java
public enum Role {
	COMPRADOR,
    VENDEDOR  
}
```

## Repositorio
En el repositorio de la clase usuario agregamos un método para buscar por el atributo que decidimos utilizar como **username**, en este caso el **email**.

```java
public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email); 
}
```


## SecurityConfig

- Esta clase contiene la **SecurityFilterChain**. Todas las requests que reciba nuestra API pasarán por esta cadena de filtros.<br>
- Le indicamos que los endpoints en la ruta /auth/ (login y registro) serán públicos (son los de la clase AuthController) . <br>
- Para acceder a los demás endpoints, el usuario deberá estar autenticado (   .anyRequest().authenticated() )<br>
- Deshabilitamos csrf y session. Son métodos predeterminados de Spring Security que no usaremos, porque la autenticación la haremos con JWT.
- Agregamos el **jwtAuthenticationFilter**.<br>
- El authenticationProvider es el responsable de recibir una solicitud de autorización y decidir si es válida o no.<br>
- La anotación @EnableMethodSecurity(securedEnabled = true) nos permitirá incluir en los controladores la anotación **@Secured** para indicar el **ROL** de los usuarios que tendrán acceso a los mismos.<br>


```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        return http
            .csrf(csrf -> 
                csrf
                .disable())
            .authorizeHttpRequests(authRequest ->
              authRequest
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
                )
            .sessionManagement(sessionManager->
                sessionManager 
                  .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
```
<br>




## JwtAuthenticationFilter

- El filtro hereda de OncePerRequestFilter (se ejecutará una vez sola por cada request).
- Obtenemos el token que viene incluido en la request llamando al método getTokenFromRequest. El mismo busca el token que está en el HEADER de la request y le quita la palabra "Bearer".
- Si la request no tiene JWT, continuamos con la cadena de filtros, donde habíamos indicado que solo podría acceder al login y registro en /auth/.
- Si la request viene con un JWT, buscará el usuario en nuestra Base de Datos. Luego lo validará (credenciales correctas, no expirado) y si está todo ok lo guardará en el SecurityContextHolder.
- SecurityContextHolder es un método estático para recuperar los datos del usuario. Permitirá llamarlo desde cualquier parte de nuestro código sin pasarle ningún parámetro.



```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       
        final String token = getTokenFromRequest(request);
        final String username;

        if (token==null)
        {
            filterChain.doFilter(request, response);
            return;
        }

        username=jwtService.getUsernameFromToken(token);

        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(token, userDetails))
            {
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer "))
        {
            return authHeader.substring(7);
        }
        return null;
    } 
}
```

## AppConfig
- **AuthenticationManager** es una interfaz de de Spring Security, responsable de manejar el proceso de autenticación de usuarios.
- El proveedor de autenticación a implementar será **DaoAuthenticationProvider**, que valida las credenciales (usuario y contraseña) contra una Base de Datos. 
- Para encriptar las contraseñas utilizaremos el algoritmo **Bycrypt**.
- **UserDetailsService** se encargará de buscar el usuario en la base de datos. Recordemos que habíamos definido que utilizaríamos como username el **email**.
- **CORS** (Cross-Origin Resource Sharing) es un mecanismo de seguridad que tienen los navegadores web para restringir peticiones HTTP entre distintos servidores. Es necesario agregar esta configuración para que el Front pueda acceder a nuestra API. Completa la línea de .allowedOrigins(... ) con la URL que utilizará el front-end.


```java
@Configuration
@RequiredArgsConstructor
public class AppConfig {

    private final UserRepository userRepository;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception
    {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider()
    {
        DaoAuthenticationProvider authenticationProvider= new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailService() {
        return username -> userRepository.findByEmail(username)
        .orElseThrow(()-> new UsernameNotFoundException("User not fournd"));
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(@NotNull CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:5173")  // URL del Front-end
                        .allowedMethods("GET", "POST", "PUT", "DELETE","OPTIONS")
                        .allowCredentials(true);
            }
        };
    } 
}
```


## JWTService
Este servicio contendrá métodos para generar el JWT, verificar su validez y extraer información del mismo.
- La SECRET_KEY sirve para validar la firma del token. Con la anotación @Value le asignamos el valor de la variable jwt.secret, que guardamos en el archivo application.properties (ver más abajo).
- El método getToken recibirá por parámetro un usuario de Spring Security (UserDetails), y construirá un JWT. Su firma se realiza con la SECRET_KEY y el algoritmo HS256.
- La expiración del token se expresa en milisegundos. Un día tiene 86400 segundos (60 seg x 60 min x 24 hs.). Este token expirará en un día.
- El método **isTokenValid** verifica si el token es válido comprobando el username (getUsernameFromToken) y su expiración (isTokenExpired)

```java
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    private String getToken(Map<String,Object> extraClaims, UserDetails user) {
        return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis()+1000*86400))
            .signWith(getKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    private Key getKey() {
       byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
       return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username=getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    private Claims getAllClaims(String token)
    {
        return Jwts
            .parserBuilder()
            .setSigningKey(getKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public <T> T getClaim(String token, Function<Claims,T> claimsResolver)
    {
        final Claims claims=getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token)
    {
        return getClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token)
    {
        return getExpiration(token).before(new Date());
    }
    
}
```
## Configurar base de datos 
- Crear una base de datos de nombre "security".
- Revisar en application.properties las credenciales de acceso

Application.properties :
```properties
spring.jpa.hibernate.ddl-auto=update
spring.datasource.url= jdbc:mysql://localhost:3306/security?useSSL=false&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=password
spring.jpa.database-platform=org.hibernate.dialect.MySQL8Dialect
jwt.secret= 123456789654564564dsa65f4s56d4f65sdf56sd564f65sdf65sd6f54sd6f

```



## AuthService
- Registro: Recibe el DTO con los datos de registro, el cual incluye el email. Si ya existe un usuario en la Base de Datos con ese email, lanzará un mensaje de error. De lo contrario guardará el usuario en la BD y devolverá el JWT llamando al JWTService del paso anterior.
- Login: Autentica al usuario con las credenciales que recibe dentro del LoginDto. Busca al usuario en la BD y genera el JWT.


```java
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginDto datos) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(datos.getEmail(), datos.getPassword()));
        UserDetails user = userRepository.findByEmail(datos.getEmail()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
            .token(token)
            .build();

    }

    public AuthResponse registro(RegistroDto datos) {
    	
        Optional<User> userOptional = userRepository.findByEmail(datos.getEmail());
        if (userOptional.isPresent()) {
            throw new RuntimeException("Ya existe un usuario con ese email");
        }
        
        User user = User.builder()
            .email(datos.getEmail())
            .password(passwordEncoder.encode(datos.getPassword()))
            .nombre(datos.getNombre())
            .apellido(datos.getApellido())
            .pais(datos.getPais())
            .role(Role.valueOf(datos.getRol()))
            .build();

        userRepository.save(user);

        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();
       
    }
}
```

## Asignar Roles de acceso a los endpoints
Mediante la anotación @Secured("ROL") indicamos el rol que debe tener el usuario para poder acceder a cada endpoint. Recordemos que para que esta anotación funcione, pusimos esta otra anotación en SecurityConfig: @EnableMethodSecurity(securedEnabled = true).<br>
Si varios roles tienen permiso a ese endpoint se puede poner así: @Secured({"ADMIN", "ROL1", "ROL2"})
<br>
Aquí tenemos una clase controlador con unos endpoints de ejemplo:
- probando: podrá ser accedido por cualquier usuario que esté logueado, independientemente de su rol, ya que no utilizamos la anotación @Secured.
- endpointComprador: solo podrá ser accedido por un usuario con rol "COMPRADOR". Si el usuario tiene otro rol, devolverá un 403.
- endpointVendedor: solo podrá ser accedido por un usuario con rol "VENDEDOR". Si el usuario tiene otro rol, devolverá un 403.


```java
@RestController
@RequestMapping("/test")
@RequiredArgsConstructor
public class TestController {
    
    @GetMapping()
    public String probando() {
        return "Hola Mundo";
    }
    
    @Secured("COMPRADOR")
    @GetMapping("endpointComprador")
    public String endpointComprador() {
        return "Hola, soy un comprador";
    }
    
    @Secured("VENDEDOR")
    @GetMapping("endpointVendedor")
    public String endpointVendedor() {
        return "Hola, soy un vendedor";
    }
    
}
```



