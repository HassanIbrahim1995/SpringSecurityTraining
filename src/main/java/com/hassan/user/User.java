package com.hassan.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;
import java.util.Set;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
@Table(name = "users")
public class User implements UserDetails {

    public User(String firstname, String lastname, String email, String password) {
        this.firstname = firstname;
        this.lastname = lastname;
        this.email = email;
        this.password = password;
        setCreatedAtFormatted();
    }

    @Id
    @Column
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50)
    @NotBlank(message = "First name cannot be blank.")
    private String firstname;

    @Column(length = 50)
    @NotBlank(message = "Last name cannot be blank.")
    private String lastname;

    @Column(length = 100)
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email cannot be blank.")
    private String email;

    @Column(length = 50)
    @NotBlank(message = "Username cannot be blank.")
    private String username;

    @Column(length = 100)
    @NotBlank(message = "Password cannot be blank.")
    private String password;

    @Column(name = "created_at", updatable = false)
    @JsonFormat(pattern = "dd-MM-yyyy HH:mm:ss")
    @JsonProperty("created_at")
    private Date createdAt;

    @Enumerated
    @NotBlank(message = "Role cannot be blank.")
    private Role role;

    @PrePersist
    public void setCreatedAtFormatted() {
        this.createdAt = new Date();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Set.of(new SimpleGrantedAuthority(role.getName()));
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
